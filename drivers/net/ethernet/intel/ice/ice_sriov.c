// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018, Intel Corporation. */

#include "ice.h"
#include "ice_vf_lib_private.h"
#include "ice_base.h"
#include "ice_lib.h"
#include "ice_fltr.h"
#include "ice_dcb_lib.h"
#include "ice_flow.h"
#include "ice_eswitch.h"
#include "ice_virtchnl_allowlist.h"
#include "ice_flex_pipe.h"
#include "ice_vf_vsi_vlan_ops.h"
#include "ice_vlan.h"

/**
 * ice_free_vf_entries - Free all VF entries from the hash table
 * @pf: pointer to the PF structure
 *
 * Iterate over the VF hash table, removing and releasing all VF entries.
 * Called during VF teardown or as cleanup during failed VF initialization.
 */
static void ice_free_vf_entries(struct ice_pf *pf)
{
	struct ice_vfs *vfs = &pf->vfs;
	struct hlist_node *tmp;
	struct ice_vf *vf;
	unsigned int bkt;

	/* Remove all VFs from the hash table and release their main
	 * reference. Once all references to the VF are dropped, ice_put_vf()
	 * will call ice_release_vf which will remove the VF memory.
	 */
	lockdep_assert_held(&vfs->table_lock);

	hash_for_each_safe(vfs->table, bkt, tmp, vf, entry) {
		hash_del_rcu(&vf->entry);
		ice_deinitialize_vf_entry(vf);
		ice_put_vf(vf);
	}
}

/**
 * ice_free_vf_res - Free a VF's resources
 * @vf: pointer to the VF info
 */
static void ice_free_vf_res(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;
	int i, last_vector_idx;

	/* First, disable VF's configuration API to prevent OS from
	 * accessing the VF's VSI after it's freed or invalidated.
	 */
	clear_bit(ICE_VF_STATE_INIT, vf->vf_states);
	ice_vf_fdir_exit(vf);
	/* free VF control VSI */
	if (vf->ctrl_vsi_idx != ICE_NO_VSI)
		ice_vf_ctrl_vsi_release(vf);

	/* free VSI and disconnect it from the parent uplink */
	if (vf->lan_vsi_idx != ICE_NO_VSI) {
		ice_vf_vsi_release(vf);
		vf->num_mac = 0;
		vf->num_mac_lldp = 0;
	}

	last_vector_idx = vf->first_vector_idx + vf->num_msix - 1;

	/* clear VF MDD event information */
	memset(&vf->mdd_tx_events, 0, sizeof(vf->mdd_tx_events));
	memset(&vf->mdd_rx_events, 0, sizeof(vf->mdd_rx_events));

	/* Disable interrupts so that VF starts in a known state */
	for (i = vf->first_vector_idx; i <= last_vector_idx; i++) {
		wr32(&pf->hw, GLINT_DYN_CTL(i), GLINT_DYN_CTL_CLEARPBA_M);
		ice_flush(&pf->hw);
	}
	/* reset some of the state variables keeping track of the resources */
	clear_bit(ICE_VF_STATE_MC_PROMISC, vf->vf_states);
	clear_bit(ICE_VF_STATE_UC_PROMISC, vf->vf_states);
}

/**
 * ice_dis_vf_mappings
 * @vf: pointer to the VF structure
 */
static void ice_dis_vf_mappings(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;
	struct device *dev;
	int first, last, v;
	struct ice_hw *hw;

	hw = &pf->hw;
	vsi = ice_get_vf_vsi(vf);
	if (WARN_ON(!vsi))
		return;

	dev = ice_pf_to_dev(pf);
	wr32(hw, VPINT_ALLOC(vf->vf_id), 0);
	wr32(hw, VPINT_ALLOC_PCI(vf->vf_id), 0);

	first = vf->first_vector_idx;
	last = first + vf->num_msix - 1;
	for (v = first; v <= last; v++) {
		u32 reg;

		reg = FIELD_PREP(GLINT_VECT2FUNC_IS_PF_M, 1) |
		      FIELD_PREP(GLINT_VECT2FUNC_PF_NUM_M, hw->pf_id);
		wr32(hw, GLINT_VECT2FUNC(v), reg);
	}

	if (vsi->tx_mapping_mode == ICE_VSI_MAP_CONTIG)
		wr32(hw, VPLAN_TX_QBASE(vf->vf_id), 0);
	else
		dev_err(dev, "Scattered mode for VF Tx queues is not yet implemented\n");

	if (vsi->rx_mapping_mode == ICE_VSI_MAP_CONTIG)
		wr32(hw, VPLAN_RX_QBASE(vf->vf_id), 0);
	else
		dev_err(dev, "Scattered mode for VF Rx queues is not yet implemented\n");
}

/**
 * ice_free_vfs - Free all VFs
 * @pf: pointer to the PF structure
 */
void ice_free_vfs(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_vfs *vfs = &pf->vfs;
	struct ice_hw *hw = &pf->hw;
	struct ice_vf *vf;
	unsigned int bkt;

	if (!ice_has_vfs(pf))
		return;

	while (test_and_set_bit(ICE_VF_DIS, pf->state))
		usleep_range(1000, 2000);

	/* Disable IOV before freeing resources. This lets any VF drivers
	 * running in the host get themselves cleaned up before we yank
	 * the carpet out from underneath their feet.
	 */
	if (!pci_vfs_assigned(pf->pdev))
		pci_disable_sriov(pf->pdev);
	else
		dev_warn(dev, "VFs are assigned - not disabling SR-IOV\n");

	mutex_lock(&vfs->table_lock);

	ice_for_each_vf(pf, bkt, vf) {
		mutex_lock(&vf->cfg_lock);

		ice_eswitch_detach_vf(pf, vf);
		ice_dis_vf_qs(vf);
		ice_virt_free_irqs(pf, vf->first_vector_idx, vf->num_msix);

		if (test_bit(ICE_VF_STATE_INIT, vf->vf_states)) {
			/* disable VF qp mappings and set VF disable state */
			ice_dis_vf_mappings(vf);
			set_bit(ICE_VF_STATE_DIS, vf->vf_states);
			ice_free_vf_res(vf);
		}

		if (!pci_vfs_assigned(pf->pdev)) {
			u32 reg_idx, bit_idx;

			reg_idx = (hw->func_caps.vf_base_id + vf->vf_id) / 32;
			bit_idx = (hw->func_caps.vf_base_id + vf->vf_id) % 32;
			wr32(hw, GLGEN_VFLRSTAT(reg_idx), BIT(bit_idx));
		}

		mutex_unlock(&vf->cfg_lock);
	}

	vfs->num_qps_per = 0;
	ice_free_vf_entries(pf);

	mutex_unlock(&vfs->table_lock);

	clear_bit(ICE_VF_DIS, pf->state);
	clear_bit(ICE_FLAG_SRIOV_ENA, pf->flags);
}

/**
 * ice_vf_vsi_setup - Set up a VF VSI
 * @vf: VF to setup VSI for
 *
 * Returns pointer to the successfully allocated VSI struct on success,
 * otherwise returns NULL on failure.
 */
static struct ice_vsi *ice_vf_vsi_setup(struct ice_vf *vf)
{
	struct ice_vsi_cfg_params params = {};
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;

	params.type = ICE_VSI_VF;
	params.port_info = ice_vf_get_port_info(vf);
	params.vf = vf;
	params.flags = ICE_VSI_FLAG_INIT;

	vsi = ice_vsi_setup(pf, &params);

	if (!vsi) {
		dev_err(ice_pf_to_dev(pf), "Failed to create VF VSI\n");
		ice_vf_invalidate_vsi(vf);
		return NULL;
	}

	vf->lan_vsi_idx = vsi->idx;

	return vsi;
}


/**
 * ice_ena_vf_msix_mappings - enable VF MSIX mappings in hardware
 * @vf: VF to enable MSIX mappings for
 *
 * Some of the registers need to be indexed/configured using hardware global
 * device values and other registers need 0-based values, which represent PF
 * based values.
 */
static void ice_ena_vf_msix_mappings(struct ice_vf *vf)
{
	int device_based_first_msix, device_based_last_msix;
	int pf_based_first_msix, pf_based_last_msix, v;
	struct ice_pf *pf = vf->pf;
	int device_based_vf_id;
	struct ice_hw *hw;
	u32 reg;

	hw = &pf->hw;
	pf_based_first_msix = vf->first_vector_idx;
	pf_based_last_msix = (pf_based_first_msix + vf->num_msix) - 1;

	device_based_first_msix = pf_based_first_msix +
		pf->hw.func_caps.common_cap.msix_vector_first_id;
	device_based_last_msix =
		(device_based_first_msix + vf->num_msix) - 1;
	device_based_vf_id = vf->vf_id + hw->func_caps.vf_base_id;

	reg = FIELD_PREP(VPINT_ALLOC_FIRST_M, device_based_first_msix) |
	      FIELD_PREP(VPINT_ALLOC_LAST_M, device_based_last_msix) |
	      VPINT_ALLOC_VALID_M;
	wr32(hw, VPINT_ALLOC(vf->vf_id), reg);

	reg = FIELD_PREP(VPINT_ALLOC_PCI_FIRST_M, device_based_first_msix) |
	      FIELD_PREP(VPINT_ALLOC_PCI_LAST_M, device_based_last_msix) |
	      VPINT_ALLOC_PCI_VALID_M;
	wr32(hw, VPINT_ALLOC_PCI(vf->vf_id), reg);

	/* map the interrupts to its functions */
	for (v = pf_based_first_msix; v <= pf_based_last_msix; v++) {
		reg = FIELD_PREP(GLINT_VECT2FUNC_VF_NUM_M, device_based_vf_id) |
		      FIELD_PREP(GLINT_VECT2FUNC_PF_NUM_M, hw->pf_id);
		wr32(hw, GLINT_VECT2FUNC(v), reg);
	}

	/* Map mailbox interrupt to VF MSI-X vector 0 */
	wr32(hw, VPINT_MBX_CTL(device_based_vf_id), VPINT_MBX_CTL_CAUSE_ENA_M);
}

/**
 * ice_ena_vf_q_mappings - enable Rx/Tx queue mappings for a VF
 * @vf: VF to enable the mappings for
 * @max_txq: max Tx queues allowed on the VF's VSI
 * @max_rxq: max Rx queues allowed on the VF's VSI
 */
static void ice_ena_vf_q_mappings(struct ice_vf *vf, u16 max_txq, u16 max_rxq)
{
	struct device *dev = ice_pf_to_dev(vf->pf);
	struct ice_vsi *vsi = ice_get_vf_vsi(vf);
	struct ice_hw *hw = &vf->pf->hw;
	u32 reg;

	if (WARN_ON(!vsi))
		return;

	/* set regardless of mapping mode */
	wr32(hw, VPLAN_TXQ_MAPENA(vf->vf_id), VPLAN_TXQ_MAPENA_TX_ENA_M);

	/* VF Tx queues allocation */
	if (vsi->tx_mapping_mode == ICE_VSI_MAP_CONTIG) {
		/* set the VF PF Tx queue range
		 * VFNUMQ value should be set to (number of queues - 1). A value
		 * of 0 means 1 queue and a value of 255 means 256 queues
		 */
		reg = FIELD_PREP(VPLAN_TX_QBASE_VFFIRSTQ_M, vsi->txq_map[0]) |
		      FIELD_PREP(VPLAN_TX_QBASE_VFNUMQ_M, max_txq - 1);
		wr32(hw, VPLAN_TX_QBASE(vf->vf_id), reg);
	} else {
		dev_err(dev, "Scattered mode for VF Tx queues is not yet implemented\n");
	}

	/* set regardless of mapping mode */
	wr32(hw, VPLAN_RXQ_MAPENA(vf->vf_id), VPLAN_RXQ_MAPENA_RX_ENA_M);

	/* VF Rx queues allocation */
	if (vsi->rx_mapping_mode == ICE_VSI_MAP_CONTIG) {
		/* set the VF PF Rx queue range
		 * VFNUMQ value should be set to (number of queues - 1). A value
		 * of 0 means 1 queue and a value of 255 means 256 queues
		 */
		reg = FIELD_PREP(VPLAN_RX_QBASE_VFFIRSTQ_M, vsi->rxq_map[0]) |
		      FIELD_PREP(VPLAN_RX_QBASE_VFNUMQ_M, max_rxq - 1);
		wr32(hw, VPLAN_RX_QBASE(vf->vf_id), reg);
	} else {
		dev_err(dev, "Scattered mode for VF Rx queues is not yet implemented\n");
	}
}

/**
 * ice_ena_vf_mappings - enable VF MSIX and queue mapping
 * @vf: pointer to the VF structure
 */
static void ice_ena_vf_mappings(struct ice_vf *vf)
{
	struct ice_vsi *vsi = ice_get_vf_vsi(vf);

	if (WARN_ON(!vsi))
		return;

	ice_ena_vf_msix_mappings(vf);
	ice_ena_vf_q_mappings(vf, vsi->alloc_txq, vsi->alloc_rxq);
}

/**
 * ice_calc_vf_reg_idx - Calculate the VF's register index in the PF space
 * @vf: VF to calculate the register index for
 * @q_vector: a q_vector associated to the VF
 */
void ice_calc_vf_reg_idx(struct ice_vf *vf, struct ice_q_vector *q_vector)
{
	if (!vf || !q_vector)
		return;

	/* always add one to account for the OICR being the first MSIX */
	q_vector->vf_reg_idx = q_vector->v_idx + ICE_NONQ_VECS_VF;
	q_vector->reg_idx = vf->first_vector_idx + q_vector->vf_reg_idx;
}

/**
 * ice_set_per_vf_res - check if vectors and queues are available
 * @pf: pointer to the PF structure
 * @num_vfs: the number of SR-IOV VFs being configured
 *
 * First, determine HW interrupts from common pool. If we allocate fewer VFs, we
 * get more vectors and can enable more queues per VF. Note that this does not
 * grab any vectors from the SW pool already allocated. Also note, that all
 * vector counts include one for each VF's miscellaneous interrupt vector
 * (i.e. OICR).
 *
 * Minimum VFs - 2 vectors, 1 queue pair
 * Small VFs - 5 vectors, 4 queue pairs
 * Medium VFs - 17 vectors, 16 queue pairs
 *
 * Second, determine number of queue pairs per VF by starting with a pre-defined
 * maximum each VF supports. If this is not possible, then we adjust based on
 * queue pairs available on the device.
 *
 * Lastly, set queue and MSI-X VF variables tracked by the PF so it can be used
 * by each VF during VF initialization and reset.
 */
static int ice_set_per_vf_res(struct ice_pf *pf, u16 num_vfs)
{
	u16 num_msix_per_vf, num_txq, num_rxq, avail_qs;
	int msix_avail_per_vf, msix_avail_for_sriov;
	struct device *dev = ice_pf_to_dev(pf);

	lockdep_assert_held(&pf->vfs.table_lock);

	if (!num_vfs)
		return -EINVAL;

	/* determine MSI-X resources per VF */
	msix_avail_for_sriov = pf->virt_irq_tracker.num_entries;
	msix_avail_per_vf = msix_avail_for_sriov / num_vfs;
	if (msix_avail_per_vf >= ICE_NUM_VF_MSIX_MED) {
		num_msix_per_vf = ICE_NUM_VF_MSIX_MED;
	} else if (msix_avail_per_vf >= ICE_NUM_VF_MSIX_SMALL) {
		num_msix_per_vf = ICE_NUM_VF_MSIX_SMALL;
	} else if (msix_avail_per_vf >= ICE_NUM_VF_MSIX_MULTIQ_MIN) {
		num_msix_per_vf = ICE_NUM_VF_MSIX_MULTIQ_MIN;
	} else if (msix_avail_per_vf >= ICE_MIN_INTR_PER_VF) {
		num_msix_per_vf = ICE_MIN_INTR_PER_VF;
	} else {
		dev_err(dev, "Only %d MSI-X interrupts available for SR-IOV. Not enough to support minimum of %d MSI-X interrupts per VF for %d VFs\n",
			msix_avail_for_sriov, ICE_MIN_INTR_PER_VF,
			num_vfs);
		return -ENOSPC;
	}

	num_txq = min_t(u16, num_msix_per_vf - ICE_NONQ_VECS_VF,
			ICE_MAX_RSS_QS_PER_VF);
	avail_qs = ice_get_avail_txq_count(pf) / num_vfs;
	if (!avail_qs)
		num_txq = 0;
	else if (num_txq > avail_qs)
		num_txq = rounddown_pow_of_two(avail_qs);

	num_rxq = min_t(u16, num_msix_per_vf - ICE_NONQ_VECS_VF,
			ICE_MAX_RSS_QS_PER_VF);
	avail_qs = ice_get_avail_rxq_count(pf) / num_vfs;
	if (!avail_qs)
		num_rxq = 0;
	else if (num_rxq > avail_qs)
		num_rxq = rounddown_pow_of_two(avail_qs);

	if (num_txq < ICE_MIN_QS_PER_VF || num_rxq < ICE_MIN_QS_PER_VF) {
		dev_err(dev, "Not enough queues to support minimum of %d queue pairs per VF for %d VFs\n",
			ICE_MIN_QS_PER_VF, num_vfs);
		return -ENOSPC;
	}

	/* only allow equal Tx/Rx queue count (i.e. queue pairs) */
	pf->vfs.num_qps_per = min_t(int, num_txq, num_rxq);
	pf->vfs.num_msix_per = num_msix_per_vf;
	dev_info(dev, "Enabling %d VFs with %d vectors and %d queues per VF\n",
		 num_vfs, pf->vfs.num_msix_per, pf->vfs.num_qps_per);

	return 0;
}

/**
 * ice_init_vf_vsi_res - initialize/setup VF VSI resources
 * @vf: VF to initialize/setup the VSI for
 *
 * This function creates a VSI for the VF, adds a VLAN 0 filter, and sets up the
 * VF VSI's broadcast filter and is only used during initial VF creation.
 */
static int ice_init_vf_vsi_res(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;
	int err;

	vf->first_vector_idx = ice_virt_get_irqs(pf, vf->num_msix);
	if (vf->first_vector_idx < 0)
		return -ENOMEM;

	vsi = ice_vf_vsi_setup(vf);
	if (!vsi)
		return -ENOMEM;

	err = ice_vf_init_host_cfg(vf, vsi);
	if (err)
		goto release_vsi;

	return 0;

release_vsi:
	ice_vf_vsi_release(vf);
	return err;
}

/**
 * ice_start_vfs - start VFs so they are ready to be used by SR-IOV
 * @pf: PF the VFs are associated with
 */
static int ice_start_vfs(struct ice_pf *pf)
{
	struct ice_hw *hw = &pf->hw;
	unsigned int bkt, it_cnt;
	struct ice_vf *vf;
	int retval;

	lockdep_assert_held(&pf->vfs.table_lock);

	it_cnt = 0;
	ice_for_each_vf(pf, bkt, vf) {
		vf->vf_ops->clear_reset_trigger(vf);

		retval = ice_init_vf_vsi_res(vf);
		if (retval) {
			dev_err(ice_pf_to_dev(pf), "Failed to initialize VSI resources for VF %d, error %d\n",
				vf->vf_id, retval);
			goto teardown;
		}

		retval = ice_eswitch_attach_vf(pf, vf);
		if (retval) {
			dev_err(ice_pf_to_dev(pf), "Failed to attach VF %d to eswitch, error %d",
				vf->vf_id, retval);
			ice_vf_vsi_release(vf);
			goto teardown;
		}

		set_bit(ICE_VF_STATE_INIT, vf->vf_states);
		ice_ena_vf_mappings(vf);
		wr32(hw, VFGEN_RSTAT(vf->vf_id), VIRTCHNL_VFR_VFACTIVE);
		it_cnt++;
	}

	ice_flush(hw);
	return 0;

teardown:
	ice_for_each_vf(pf, bkt, vf) {
		if (it_cnt == 0)
			break;

		ice_dis_vf_mappings(vf);
		ice_vf_vsi_release(vf);
		it_cnt--;
	}

	return retval;
}

/**
 * ice_sriov_free_vf - Free VF memory after all references are dropped
 * @vf: pointer to VF to free
 *
 * Called by ice_put_vf through ice_release_vf once the last reference to a VF
 * structure has been dropped.
 */
static void ice_sriov_free_vf(struct ice_vf *vf)
{
	mutex_destroy(&vf->cfg_lock);

	kfree_rcu(vf, rcu);
}

/**
 * ice_sriov_clear_reset_state - clears VF Reset status register
 * @vf: the vf to configure
 */
static void ice_sriov_clear_reset_state(struct ice_vf *vf)
{
	struct ice_hw *hw = &vf->pf->hw;

	/* Clear the reset status register so that VF immediately sees that
	 * the device is resetting, even if hardware hasn't yet gotten around
	 * to clearing VFGEN_RSTAT for us.
	 */
	wr32(hw, VFGEN_RSTAT(vf->vf_id), VIRTCHNL_VFR_INPROGRESS);
}

/**
 * ice_sriov_clear_mbx_register - clears SRIOV VF's mailbox registers
 * @vf: the vf to configure
 */
static void ice_sriov_clear_mbx_register(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;

	wr32(&pf->hw, VF_MBX_ARQLEN(vf->vf_id), 0);
	wr32(&pf->hw, VF_MBX_ATQLEN(vf->vf_id), 0);
}

/**
 * ice_sriov_trigger_reset_register - trigger VF reset for SRIOV VF
 * @vf: pointer to VF structure
 * @is_vflr: true if reset occurred due to VFLR
 *
 * Trigger and cleanup after a VF reset for a SR-IOV VF.
 */
static void ice_sriov_trigger_reset_register(struct ice_vf *vf, bool is_vflr)
{
	struct ice_pf *pf = vf->pf;
	u32 reg, reg_idx, bit_idx;
	unsigned int vf_abs_id, i;
	struct device *dev;
	struct ice_hw *hw;

	dev = ice_pf_to_dev(pf);
	hw = &pf->hw;
	vf_abs_id = vf->vf_id + hw->func_caps.vf_base_id;

	/* In the case of a VFLR, HW has already reset the VF and we just need
	 * to clean up. Otherwise we must first trigger the reset using the
	 * VFRTRIG register.
	 */
	if (!is_vflr) {
		reg = rd32(hw, VPGEN_VFRTRIG(vf->vf_id));
		reg |= VPGEN_VFRTRIG_VFSWR_M;
		wr32(hw, VPGEN_VFRTRIG(vf->vf_id), reg);
	}

	/* clear the VFLR bit in GLGEN_VFLRSTAT */
	reg_idx = (vf_abs_id) / 32;
	bit_idx = (vf_abs_id) % 32;
	wr32(hw, GLGEN_VFLRSTAT(reg_idx), BIT(bit_idx));
	ice_flush(hw);

	wr32(hw, PF_PCI_CIAA,
	     VF_DEVICE_STATUS | (vf_abs_id << PF_PCI_CIAA_VF_NUM_S));
	for (i = 0; i < ICE_PCI_CIAD_WAIT_COUNT; i++) {
		reg = rd32(hw, PF_PCI_CIAD);
		/* no transactions pending so stop polling */
		if ((reg & VF_TRANS_PENDING_M) == 0)
			break;

		dev_err(dev, "VF %u PCI transactions stuck\n", vf->vf_id);
		udelay(ICE_PCI_CIAD_WAIT_DELAY_US);
	}
}

/**
 * ice_sriov_poll_reset_status - poll SRIOV VF reset status
 * @vf: pointer to VF structure
 *
 * Returns true when reset is successful, else returns false
 */
static bool ice_sriov_poll_reset_status(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;
	unsigned int i;
	u32 reg;

	for (i = 0; i < 10; i++) {
		/* VF reset requires driver to first reset the VF and then
		 * poll the status register to make sure that the reset
		 * completed successfully.
		 */
		reg = rd32(&pf->hw, VPGEN_VFRSTAT(vf->vf_id));
		if (reg & VPGEN_VFRSTAT_VFRD_M)
			return true;

		/* only sleep if the reset is not done */
		usleep_range(10, 20);
	}
	return false;
}

/**
 * ice_sriov_clear_reset_trigger - enable VF to access hardware
 * @vf: VF to enabled hardware access for
 */
static void ice_sriov_clear_reset_trigger(struct ice_vf *vf)
{
	struct ice_hw *hw = &vf->pf->hw;
	u32 reg;

	reg = rd32(hw, VPGEN_VFRTRIG(vf->vf_id));
	reg &= ~VPGEN_VFRTRIG_VFSWR_M;
	wr32(hw, VPGEN_VFRTRIG(vf->vf_id), reg);
	ice_flush(hw);
}

/**
 * ice_sriov_post_vsi_rebuild - tasks to do after the VF's VSI have been rebuilt
 * @vf: VF to perform tasks on
 */
static void ice_sriov_post_vsi_rebuild(struct ice_vf *vf)
{
	ice_ena_vf_mappings(vf);
	wr32(&vf->pf->hw, VFGEN_RSTAT(vf->vf_id), VIRTCHNL_VFR_VFACTIVE);
}

static const struct ice_vf_ops ice_sriov_vf_ops = {
	.reset_type = ICE_VF_RESET,
	.free = ice_sriov_free_vf,
	.clear_reset_state = ice_sriov_clear_reset_state,
	.clear_mbx_register = ice_sriov_clear_mbx_register,
	.trigger_reset_register = ice_sriov_trigger_reset_register,
	.poll_reset_status = ice_sriov_poll_reset_status,
	.clear_reset_trigger = ice_sriov_clear_reset_trigger,
	.irq_close = NULL,
	.post_vsi_rebuild = ice_sriov_post_vsi_rebuild,
};

/**
 * ice_create_vf_entries - Allocate and insert VF entries
 * @pf: pointer to the PF structure
 * @num_vfs: the number of VFs to allocate
 *
 * Allocate new VF entries and insert them into the hash table. Set some
 * basic default fields for initializing the new VFs.
 *
 * After this function exits, the hash table will have num_vfs entries
 * inserted.
 *
 * Returns 0 on success or an integer error code on failure.
 */
static int ice_create_vf_entries(struct ice_pf *pf, u16 num_vfs)
{
	struct pci_dev *pdev = pf->pdev;
	struct ice_vfs *vfs = &pf->vfs;
	struct pci_dev *vfdev = NULL;
	struct ice_vf *vf;
	u16 vf_pdev_id;
	int err, pos;

	lockdep_assert_held(&vfs->table_lock);

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);
	pci_read_config_word(pdev, pos + PCI_SRIOV_VF_DID, &vf_pdev_id);

	for (u16 vf_id = 0; vf_id < num_vfs; vf_id++) {
		vf = kzalloc(sizeof(*vf), GFP_KERNEL);
		if (!vf) {
			err = -ENOMEM;
			goto err_free_entries;
		}
		kref_init(&vf->refcnt);

		vf->pf = pf;
		vf->vf_id = vf_id;

		/* set sriov vf ops for VFs created during SRIOV flow */
		vf->vf_ops = &ice_sriov_vf_ops;

		ice_initialize_vf_entry(vf);

		do {
			vfdev = pci_get_device(pdev->vendor, vf_pdev_id, vfdev);
		} while (vfdev && vfdev->physfn != pdev);
		vf->vfdev = vfdev;
		vf->vf_sw_id = pf->first_sw;

		pci_dev_get(vfdev);

		hash_add_rcu(vfs->table, &vf->entry, vf_id);
	}

	/* Decrement of refcount done by pci_get_device() inside the loop does
	 * not touch the last iteration's vfdev, so it has to be done manually
	 * to balance pci_dev_get() added within the loop.
	 */
	pci_dev_put(vfdev);

	return 0;

err_free_entries:
	ice_free_vf_entries(pf);
	return err;
}

/**
 * ice_ena_vfs - enable VFs so they are ready to be used
 * @pf: pointer to the PF structure
 * @num_vfs: number of VFs to enable
 */
static int ice_ena_vfs(struct ice_pf *pf, u16 num_vfs)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	int ret;

	/* Disable global interrupt 0 so we don't try to handle the VFLR. */
	wr32(hw, GLINT_DYN_CTL(pf->oicr_irq.index),
	     ICE_ITR_NONE << GLINT_DYN_CTL_ITR_INDX_S);
	set_bit(ICE_OICR_INTR_DIS, pf->state);
	ice_flush(hw);

	ret = pci_enable_sriov(pf->pdev, num_vfs);
	if (ret)
		goto err_unroll_intr;

	mutex_lock(&pf->vfs.table_lock);

	ret = ice_set_per_vf_res(pf, num_vfs);
	if (ret) {
		dev_err(dev, "Not enough resources for %d VFs, err %d. Try with fewer number of VFs\n",
			num_vfs, ret);
		goto err_unroll_sriov;
	}

	ret = ice_create_vf_entries(pf, num_vfs);
	if (ret) {
		dev_err(dev, "Failed to allocate VF entries for %d VFs\n",
			num_vfs);
		goto err_unroll_sriov;
	}

	ret = ice_start_vfs(pf);
	if (ret) {
		dev_err(dev, "Failed to start %d VFs, err %d\n", num_vfs, ret);
		ret = -EAGAIN;
		goto err_unroll_vf_entries;
	}

	clear_bit(ICE_VF_DIS, pf->state);

	/* rearm global interrupts */
	if (test_and_clear_bit(ICE_OICR_INTR_DIS, pf->state))
		ice_irq_dynamic_ena(hw, NULL, NULL);

	mutex_unlock(&pf->vfs.table_lock);

	return 0;

err_unroll_vf_entries:
	ice_free_vf_entries(pf);
err_unroll_sriov:
	mutex_unlock(&pf->vfs.table_lock);
	pci_disable_sriov(pf->pdev);
err_unroll_intr:
	/* rearm interrupts here */
	ice_irq_dynamic_ena(hw, NULL, NULL);
	clear_bit(ICE_OICR_INTR_DIS, pf->state);
	return ret;
}

/**
 * ice_pci_sriov_ena - Enable or change number of VFs
 * @pf: pointer to the PF structure
 * @num_vfs: number of VFs to allocate
 *
 * Returns 0 on success and negative on failure
 */
static int ice_pci_sriov_ena(struct ice_pf *pf, int num_vfs)
{
	struct device *dev = ice_pf_to_dev(pf);
	int err;

	if (!num_vfs) {
		ice_free_vfs(pf);
		return 0;
	}

	if (num_vfs > pf->vfs.num_supported) {
		dev_err(dev, "Can't enable %d VFs, max VFs supported is %d\n",
			num_vfs, pf->vfs.num_supported);
		return -EOPNOTSUPP;
	}

	dev_info(dev, "Enabling %d VFs\n", num_vfs);
	err = ice_ena_vfs(pf, num_vfs);
	if (err) {
		dev_err(dev, "Failed to enable SR-IOV: %d\n", err);
		return err;
	}

	set_bit(ICE_FLAG_SRIOV_ENA, pf->flags);
	return 0;
}

/**
 * ice_check_sriov_allowed - check if SR-IOV is allowed based on various checks
 * @pf: PF to enabled SR-IOV on
 */
static int ice_check_sriov_allowed(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);

	if (!test_bit(ICE_FLAG_SRIOV_CAPABLE, pf->flags)) {
		dev_err(dev, "This device is not capable of SR-IOV\n");
		return -EOPNOTSUPP;
	}

	if (ice_is_safe_mode(pf)) {
		dev_err(dev, "SR-IOV cannot be configured - Device is in Safe Mode\n");
		return -EOPNOTSUPP;
	}

	if (!ice_pf_state_is_nominal(pf)) {
		dev_err(dev, "Cannot enable SR-IOV, device not ready\n");
		return -EBUSY;
	}

	return 0;
}

/**
 * ice_sriov_get_vf_total_msix - return number of MSI-X used by VFs
 * @pdev: pointer to pci_dev struct
 *
 * The function is called via sysfs ops
 */
u32 ice_sriov_get_vf_total_msix(struct pci_dev *pdev)
{
	struct ice_pf *pf = pci_get_drvdata(pdev);

	return pf->virt_irq_tracker.num_entries;
}

static void ice_sriov_remap_vectors(struct ice_pf *pf, u16 restricted_id)
{
	u16 vf_ids[ICE_MAX_SRIOV_VFS];
	struct ice_vf *tmp_vf;
	int to_remap = 0, bkt;

	/* For better irqs usage try to remap irqs of VFs
	 * that aren't running yet
	 */
	ice_for_each_vf(pf, bkt, tmp_vf) {
		/* skip VF which is changing the number of MSI-X */
		if (restricted_id == tmp_vf->vf_id ||
		    test_bit(ICE_VF_STATE_ACTIVE, tmp_vf->vf_states))
			continue;

		ice_dis_vf_mappings(tmp_vf);
		ice_virt_free_irqs(pf, tmp_vf->first_vector_idx,
				   tmp_vf->num_msix);

		vf_ids[to_remap] = tmp_vf->vf_id;
		to_remap += 1;
	}

	for (int i = 0; i < to_remap; i++) {
		tmp_vf = ice_get_vf_by_id(pf, vf_ids[i]);
		if (!tmp_vf)
			continue;

		tmp_vf->first_vector_idx =
			ice_virt_get_irqs(pf, tmp_vf->num_msix);
		/* there is no need to rebuild VSI as we are only changing the
		 * vector indexes not amount of MSI-X or queues
		 */
		ice_ena_vf_mappings(tmp_vf);
		ice_put_vf(tmp_vf);
	}
}

/**
 * ice_sriov_set_msix_vec_count
 * @vf_dev: pointer to pci_dev struct of VF device
 * @msix_vec_count: new value for MSI-X amount on this VF
 *
 * Set requested MSI-X, queues and registers for @vf_dev.
 *
 * First do some sanity checks like if there are any VFs, if the new value
 * is correct etc. Then disable old mapping (MSI-X and queues registers), change
 * MSI-X and queues, rebuild VSI and enable new mapping.
 *
 * If it is possible (driver not binded to VF) try to remap also other VFs to
 * linearize irqs register usage.
 */
int ice_sriov_set_msix_vec_count(struct pci_dev *vf_dev, int msix_vec_count)
{
	struct pci_dev *pdev = pci_physfn(vf_dev);
	struct ice_pf *pf = pci_get_drvdata(pdev);
	u16 prev_msix, prev_queues, queues;
	bool needs_rebuild = false;
	struct ice_vsi *vsi;
	struct ice_vf *vf;

	if (!ice_get_num_vfs(pf))
		return -ENOENT;

	if (!msix_vec_count)
		return 0;

	queues = msix_vec_count;
	/* add 1 MSI-X for OICR */
	msix_vec_count += 1;

	if (queues > min(ice_get_avail_txq_count(pf),
			 ice_get_avail_rxq_count(pf)))
		return -EINVAL;

	if (msix_vec_count < ICE_MIN_INTR_PER_VF)
		return -EINVAL;

	vf = ice_get_vf_by_dev(pf, vf_dev);
	if (!vf)
		return -ENOENT;

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		ice_put_vf(vf);
		return -ENOENT;
	}

	/* No need to rebuild if we're setting to the same value */
	if (msix_vec_count == vf->num_msix) {
		ice_put_vf(vf);
		return 0;
	}

	prev_msix = vf->num_msix;
	prev_queues = vf->num_vf_qs;

	ice_dis_vf_mappings(vf);
	ice_virt_free_irqs(pf, vf->first_vector_idx, vf->num_msix);

	/* Remap all VFs beside the one is now configured */
	ice_sriov_remap_vectors(pf, vf->vf_id);

	vf->num_msix = msix_vec_count;
	vf->num_vf_qs = queues;
	vf->first_vector_idx = ice_virt_get_irqs(pf, vf->num_msix);
	if (vf->first_vector_idx < 0)
		goto unroll;

	vsi->req_txq = queues;
	vsi->req_rxq = queues;

	if (ice_vsi_rebuild(vsi, ICE_VSI_FLAG_NO_INIT)) {
		/* Try to rebuild with previous values */
		needs_rebuild = true;
		goto unroll;
	}

	dev_info(ice_pf_to_dev(pf),
		 "Changing VF %d resources to %d vectors and %d queues\n",
		 vf->vf_id, vf->num_msix, vf->num_vf_qs);

	ice_ena_vf_mappings(vf);
	ice_put_vf(vf);

	return 0;

unroll:
	dev_info(ice_pf_to_dev(pf),
		 "Can't set %d vectors on VF %d, falling back to %d\n",
		 vf->num_msix, vf->vf_id, prev_msix);

	vf->num_msix = prev_msix;
	vf->num_vf_qs = prev_queues;

	vf->first_vector_idx = ice_virt_get_irqs(pf, vf->num_msix);
	if (vf->first_vector_idx < 0) {
		ice_put_vf(vf);
		return -EINVAL;
	}

	if (needs_rebuild) {
		vsi->req_txq = prev_queues;
		vsi->req_rxq = prev_queues;

		ice_vsi_rebuild(vsi, ICE_VSI_FLAG_NO_INIT);
	}

	ice_ena_vf_mappings(vf);
	ice_put_vf(vf);

	return -EINVAL;
}

/**
 * ice_sriov_configure - Enable or change number of VFs via sysfs
 * @pdev: pointer to a pci_dev structure
 * @num_vfs: number of VFs to allocate or 0 to free VFs
 *
 * This function is called when the user updates the number of VFs in sysfs. On
 * success return whatever num_vfs was set to by the caller. Return negative on
 * failure.
 */
int ice_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	struct ice_pf *pf = pci_get_drvdata(pdev);
	struct device *dev = ice_pf_to_dev(pf);
	int err;

	err = ice_check_sriov_allowed(pf);
	if (err)
		return err;

	if (!num_vfs) {
		if (!pci_vfs_assigned(pdev)) {
			ice_free_vfs(pf);
			return 0;
		}

		dev_err(dev, "can't free VFs because some are assigned to VMs.\n");
		return -EBUSY;
	}

	err = ice_pci_sriov_ena(pf, num_vfs);
	if (err)
		return err;

	return num_vfs;
}

/**
 * ice_process_vflr_event - Free VF resources via IRQ calls
 * @pf: pointer to the PF structure
 *
 * called from the VFLR IRQ handler to
 * free up VF resources and state variables
 */
void ice_process_vflr_event(struct ice_pf *pf)
{
	struct ice_hw *hw = &pf->hw;
	struct ice_vf *vf;
	unsigned int bkt;
	u32 reg;

	if (!test_and_clear_bit(ICE_VFLR_EVENT_PENDING, pf->state) ||
	    !ice_has_vfs(pf))
		return;

	mutex_lock(&pf->vfs.table_lock);
	ice_for_each_vf(pf, bkt, vf) {
		u32 reg_idx, bit_idx;

		reg_idx = (hw->func_caps.vf_base_id + vf->vf_id) / 32;
		bit_idx = (hw->func_caps.vf_base_id + vf->vf_id) % 32;
		/* read GLGEN_VFLRSTAT register to find out the flr VFs */
		reg = rd32(hw, GLGEN_VFLRSTAT(reg_idx));
		if (reg & BIT(bit_idx))
			/* GLGEN_VFLRSTAT bit will be cleared in ice_reset_vf */
			ice_reset_vf(vf, ICE_VF_RESET_VFLR | ICE_VF_RESET_LOCK);
	}
	mutex_unlock(&pf->vfs.table_lock);
}

/**
 * ice_get_vf_from_pfq - get the VF who owns the PF space queue passed in
 * @pf: PF used to index all VFs
 * @pfq: queue index relative to the PF's function space
 *
 * If no VF is found who owns the pfq then return NULL, otherwise return a
 * pointer to the VF who owns the pfq
 *
 * If this function returns non-NULL, it acquires a reference count of the VF
 * structure. The caller is responsible for calling ice_put_vf() to drop this
 * reference.
 */
static struct ice_vf *ice_get_vf_from_pfq(struct ice_pf *pf, u16 pfq)
{
	struct ice_vf *vf;
	unsigned int bkt;

	rcu_read_lock();
	ice_for_each_vf_rcu(pf, bkt, vf) {
		struct ice_vsi *vsi;
		u16 rxq_idx;

		vsi = ice_get_vf_vsi(vf);
		if (!vsi)
			continue;

		ice_for_each_rxq(vsi, rxq_idx)
			if (vsi->rxq_map[rxq_idx] == pfq) {
				struct ice_vf *found;

				if (kref_get_unless_zero(&vf->refcnt))
					found = vf;
				else
					found = NULL;
				rcu_read_unlock();
				return found;
			}
	}
	rcu_read_unlock();

	return NULL;
}

/**
 * ice_globalq_to_pfq - convert from global queue index to PF space queue index
 * @pf: PF used for conversion
 * @globalq: global queue index used to convert to PF space queue index
 */
static u32 ice_globalq_to_pfq(struct ice_pf *pf, u32 globalq)
{
	return globalq - pf->hw.func_caps.common_cap.rxq_first_id;
}

/**
 * ice_vf_lan_overflow_event - handle LAN overflow event for a VF
 * @pf: PF that the LAN overflow event happened on
 * @event: structure holding the event information for the LAN overflow event
 *
 * Determine if the LAN overflow event was caused by a VF queue. If it was not
 * caused by a VF, do nothing. If a VF caused this LAN overflow event trigger a
 * reset on the offending VF.
 */
void
ice_vf_lan_overflow_event(struct ice_pf *pf, struct ice_rq_event_info *event)
{
	struct ice_aqc_event_lan_overflow *cmd;
	u32 gldcb_rtctq, queue;
	struct ice_vf *vf;

	cmd = libie_aq_raw(&event->desc);
	gldcb_rtctq = le32_to_cpu(cmd->prtdcb_ruptq);
	dev_dbg(ice_pf_to_dev(pf), "GLDCB_RTCTQ: 0x%08x\n", gldcb_rtctq);

	/* event returns device global Rx queue number */
	queue = FIELD_GET(GLDCB_RTCTQ_RXQNUM_M, gldcb_rtctq);

	vf = ice_get_vf_from_pfq(pf, ice_globalq_to_pfq(pf, queue));
	if (!vf)
		return;

	ice_reset_vf(vf, ICE_VF_RESET_NOTIFY | ICE_VF_RESET_LOCK);
	ice_put_vf(vf);
}

/**
 * ice_set_vf_spoofchk
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @ena: flag to enable or disable feature
 *
 * Enable or disable VF spoof checking
 */
int ice_set_vf_spoofchk(struct net_device *netdev, int vf_id, bool ena)
{
	struct ice_netdev_priv *np = netdev_priv(netdev);
	struct ice_pf *pf = np->vsi->back;
	struct ice_vsi *vf_vsi;
	struct device *dev;
	struct ice_vf *vf;
	int ret;

	dev = ice_pf_to_dev(pf);

	vf = ice_get_vf_by_id(pf, vf_id);
	if (!vf)
		return -EINVAL;

	ret = ice_check_vf_ready_for_cfg(vf);
	if (ret)
		goto out_put_vf;

	vf_vsi = ice_get_vf_vsi(vf);
	if (!vf_vsi) {
		netdev_err(netdev, "VSI %d for VF %d is null\n",
			   vf->lan_vsi_idx, vf->vf_id);
		ret = -EINVAL;
		goto out_put_vf;
	}

	if (vf_vsi->type != ICE_VSI_VF) {
		netdev_err(netdev, "Type %d of VSI %d for VF %d is no ICE_VSI_VF\n",
			   vf_vsi->type, vf_vsi->vsi_num, vf->vf_id);
		ret = -ENODEV;
		goto out_put_vf;
	}

	if (ena == vf->spoofchk) {
		dev_dbg(dev, "VF spoofchk already %s\n", ena ? "ON" : "OFF");
		ret = 0;
		goto out_put_vf;
	}

	ret = ice_vsi_apply_spoofchk(vf_vsi, ena);
	if (ret)
		dev_err(dev, "Failed to set spoofchk %s for VF %d VSI %d\n error %d\n",
			ena ? "ON" : "OFF", vf->vf_id, vf_vsi->vsi_num, ret);
	else
		vf->spoofchk = ena;

out_put_vf:
	ice_put_vf(vf);
	return ret;
}

/**
 * ice_get_vf_cfg
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @ivi: VF configuration structure
 *
 * return VF configuration
 */
int
ice_get_vf_cfg(struct net_device *netdev, int vf_id, struct ifla_vf_info *ivi)
{
	struct ice_pf *pf = ice_netdev_to_pf(netdev);
	struct ice_vf *vf;
	int ret;

	vf = ice_get_vf_by_id(pf, vf_id);
	if (!vf)
		return -EINVAL;

	ret = ice_check_vf_ready_for_cfg(vf);
	if (ret)
		goto out_put_vf;

	ivi->vf = vf_id;
	ether_addr_copy(ivi->mac, vf->hw_lan_addr);

	/* VF configuration for VLAN and applicable QoS */
	ivi->vlan = ice_vf_get_port_vlan_id(vf);
	ivi->qos = ice_vf_get_port_vlan_prio(vf);
	if (ice_vf_is_port_vlan_ena(vf))
		ivi->vlan_proto = cpu_to_be16(ice_vf_get_port_vlan_tpid(vf));

	ivi->trusted = vf->trusted;
	ivi->spoofchk = vf->spoofchk;
	if (!vf->link_forced)
		ivi->linkstate = IFLA_VF_LINK_STATE_AUTO;
	else if (vf->link_up)
		ivi->linkstate = IFLA_VF_LINK_STATE_ENABLE;
	else
		ivi->linkstate = IFLA_VF_LINK_STATE_DISABLE;
	ivi->max_tx_rate = vf->max_tx_rate;
	ivi->min_tx_rate = vf->min_tx_rate;

out_put_vf:
	ice_put_vf(vf);
	return ret;
}

/**
 * __ice_set_vf_mac - program VF MAC address
 * @pf: PF to be configure
 * @vf_id: VF identifier
 * @mac: MAC address
 *
 * program VF MAC address
 * Return: zero on success or an error code on failure
 */
int __ice_set_vf_mac(struct ice_pf *pf, u16 vf_id, const u8 *mac)
{
	struct device *dev;
	struct ice_vf *vf;
	int ret;

	dev = ice_pf_to_dev(pf);
	if (is_multicast_ether_addr(mac)) {
		dev_err(dev, "%pM not a valid unicast address\n", mac);
		return -EINVAL;
	}

	vf = ice_get_vf_by_id(pf, vf_id);
	if (!vf)
		return -EINVAL;

	/* nothing left to do, unicast MAC already set */
	if (ether_addr_equal(vf->dev_lan_addr, mac) &&
	    ether_addr_equal(vf->hw_lan_addr, mac)) {
		ret = 0;
		goto out_put_vf;
	}

	ret = ice_check_vf_ready_for_cfg(vf);
	if (ret)
		goto out_put_vf;

	mutex_lock(&vf->cfg_lock);

	/* VF is notified of its new MAC via the PF's response to the
	 * VIRTCHNL_OP_GET_VF_RESOURCES message after the VF has been reset
	 */
	ether_addr_copy(vf->dev_lan_addr, mac);
	ether_addr_copy(vf->hw_lan_addr, mac);
	if (is_zero_ether_addr(mac)) {
		/* VF will send VIRTCHNL_OP_ADD_ETH_ADDR message with its MAC */
		vf->pf_set_mac = false;
		dev_info(dev, "Removing MAC on VF %d. VF driver will be reinitialized\n",
			 vf->vf_id);
	} else {
		/* PF will add MAC rule for the VF */
		vf->pf_set_mac = true;
		dev_info(dev, "Setting MAC %pM on VF %d. VF driver will be reinitialized\n",
			 mac, vf_id);
	}

	ice_reset_vf(vf, ICE_VF_RESET_NOTIFY);
	mutex_unlock(&vf->cfg_lock);

out_put_vf:
	ice_put_vf(vf);
	return ret;
}

/**
 * ice_set_vf_mac - .ndo_set_vf_mac handler
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @mac: MAC address
 *
 * program VF MAC address
 * Return: zero on success or an error code on failure
 */
int ice_set_vf_mac(struct net_device *netdev, int vf_id, u8 *mac)
{
	return __ice_set_vf_mac(ice_netdev_to_pf(netdev), vf_id, mac);
}

/**
 * ice_set_vf_trust
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @trusted: Boolean value to enable/disable trusted VF
 *
 * Enable or disable a given VF as trusted
 */
int ice_set_vf_trust(struct net_device *netdev, int vf_id, bool trusted)
{
	struct ice_pf *pf = ice_netdev_to_pf(netdev);
	struct ice_vf *vf;
	int ret;

	vf = ice_get_vf_by_id(pf, vf_id);
	if (!vf)
		return -EINVAL;

	if (ice_is_eswitch_mode_switchdev(pf)) {
		dev_info(ice_pf_to_dev(pf), "Trusted VF is forbidden in switchdev mode\n");
		return -EOPNOTSUPP;
	}

	ret = ice_check_vf_ready_for_cfg(vf);
	if (ret)
		goto out_put_vf;

	/* Check if already trusted */
	if (trusted == vf->trusted) {
		ret = 0;
		goto out_put_vf;
	}

	mutex_lock(&vf->cfg_lock);

	while (!trusted && vf->num_mac_lldp)
		ice_vf_update_mac_lldp_num(vf, ice_get_vf_vsi(vf), false);

	vf->trusted = trusted;
	ice_reset_vf(vf, ICE_VF_RESET_NOTIFY);
	dev_info(ice_pf_to_dev(pf), "VF %u is now %strusted\n",
		 vf_id, trusted ? "" : "un");

	mutex_unlock(&vf->cfg_lock);

out_put_vf:
	ice_put_vf(vf);
	return ret;
}

/**
 * ice_set_vf_link_state
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @link_state: required link state
 *
 * Set VF's link state, irrespective of physical link state status
 */
int ice_set_vf_link_state(struct net_device *netdev, int vf_id, int link_state)
{
	struct ice_pf *pf = ice_netdev_to_pf(netdev);
	struct ice_vf *vf;
	int ret;

	vf = ice_get_vf_by_id(pf, vf_id);
	if (!vf)
		return -EINVAL;

	ret = ice_check_vf_ready_for_cfg(vf);
	if (ret)
		goto out_put_vf;

	switch (link_state) {
	case IFLA_VF_LINK_STATE_AUTO:
		vf->link_forced = false;
		break;
	case IFLA_VF_LINK_STATE_ENABLE:
		vf->link_forced = true;
		vf->link_up = true;
		break;
	case IFLA_VF_LINK_STATE_DISABLE:
		vf->link_forced = true;
		vf->link_up = false;
		break;
	default:
		ret = -EINVAL;
		goto out_put_vf;
	}

	ice_vc_notify_vf_link_state(vf);

out_put_vf:
	ice_put_vf(vf);
	return ret;
}

/**
 * ice_calc_all_vfs_min_tx_rate - calculate cumulative min Tx rate on all VFs
 * @pf: PF associated with VFs
 */
static int ice_calc_all_vfs_min_tx_rate(struct ice_pf *pf)
{
	struct ice_vf *vf;
	unsigned int bkt;
	int rate = 0;

	rcu_read_lock();
	ice_for_each_vf_rcu(pf, bkt, vf)
		rate += vf->min_tx_rate;
	rcu_read_unlock();

	return rate;
}

/**
 * ice_min_tx_rate_oversubscribed - check if min Tx rate causes oversubscription
 * @vf: VF trying to configure min_tx_rate
 * @min_tx_rate: min Tx rate in Mbps
 *
 * Check if the min_tx_rate being passed in will cause oversubscription of total
 * min_tx_rate based on the current link speed and all other VFs configured
 * min_tx_rate
 *
 * Return true if the passed min_tx_rate would cause oversubscription, else
 * return false
 */
static bool
ice_min_tx_rate_oversubscribed(struct ice_vf *vf, int min_tx_rate)
{
	struct ice_vsi *vsi = ice_get_vf_vsi(vf);
	int all_vfs_min_tx_rate;
	int link_speed_mbps;

	if (WARN_ON(!vsi))
		return false;

	link_speed_mbps = ice_get_link_speed_mbps(vsi);
	all_vfs_min_tx_rate = ice_calc_all_vfs_min_tx_rate(vf->pf);

	/* this VF's previous rate is being overwritten */
	all_vfs_min_tx_rate -= vf->min_tx_rate;

	if (all_vfs_min_tx_rate + min_tx_rate > link_speed_mbps) {
		dev_err(ice_pf_to_dev(vf->pf), "min_tx_rate of %d Mbps on VF %u would cause oversubscription of %d Mbps based on the current link speed %d Mbps\n",
			min_tx_rate, vf->vf_id,
			all_vfs_min_tx_rate + min_tx_rate - link_speed_mbps,
			link_speed_mbps);
		return true;
	}

	return false;
}

/**
 * ice_set_vf_bw - set min/max VF bandwidth
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @min_tx_rate: Minimum Tx rate in Mbps
 * @max_tx_rate: Maximum Tx rate in Mbps
 */
int
ice_set_vf_bw(struct net_device *netdev, int vf_id, int min_tx_rate,
	      int max_tx_rate)
{
	struct ice_pf *pf = ice_netdev_to_pf(netdev);
	struct ice_vsi *vsi;
	struct device *dev;
	struct ice_vf *vf;
	int ret;

	dev = ice_pf_to_dev(pf);

	vf = ice_get_vf_by_id(pf, vf_id);
	if (!vf)
		return -EINVAL;

	ret = ice_check_vf_ready_for_cfg(vf);
	if (ret)
		goto out_put_vf;

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		ret = -EINVAL;
		goto out_put_vf;
	}

	if (min_tx_rate && ice_is_dcb_active(pf)) {
		dev_err(dev, "DCB on PF is currently enabled. VF min Tx rate limiting not allowed on this PF.\n");
		ret = -EOPNOTSUPP;
		goto out_put_vf;
	}

	if (ice_min_tx_rate_oversubscribed(vf, min_tx_rate)) {
		ret = -EINVAL;
		goto out_put_vf;
	}

	if (vf->min_tx_rate != (unsigned int)min_tx_rate) {
		ret = ice_set_min_bw_limit(vsi, (u64)min_tx_rate * 1000);
		if (ret) {
			dev_err(dev, "Unable to set min-tx-rate for VF %d\n",
				vf->vf_id);
			goto out_put_vf;
		}

		vf->min_tx_rate = min_tx_rate;
	}

	if (vf->max_tx_rate != (unsigned int)max_tx_rate) {
		ret = ice_set_max_bw_limit(vsi, (u64)max_tx_rate * 1000);
		if (ret) {
			dev_err(dev, "Unable to set max-tx-rate for VF %d\n",
				vf->vf_id);
			goto out_put_vf;
		}

		vf->max_tx_rate = max_tx_rate;
	}

out_put_vf:
	ice_put_vf(vf);
	return ret;
}

/**
 * ice_get_vf_stats - populate some stats for the VF
 * @netdev: the netdev of the PF
 * @vf_id: the host OS identifier (0-255)
 * @vf_stats: pointer to the OS memory to be initialized
 */
int ice_get_vf_stats(struct net_device *netdev, int vf_id,
		     struct ifla_vf_stats *vf_stats)
{
	struct ice_pf *pf = ice_netdev_to_pf(netdev);
	struct ice_eth_stats *stats;
	struct ice_vsi *vsi;
	struct ice_vf *vf;
	int ret;

	vf = ice_get_vf_by_id(pf, vf_id);
	if (!vf)
		return -EINVAL;

	ret = ice_check_vf_ready_for_cfg(vf);
	if (ret)
		goto out_put_vf;

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		ret = -EINVAL;
		goto out_put_vf;
	}

	ice_update_eth_stats(vsi);
	stats = &vsi->eth_stats;

	memset(vf_stats, 0, sizeof(*vf_stats));

	vf_stats->rx_packets = stats->rx_unicast + stats->rx_broadcast +
		stats->rx_multicast;
	vf_stats->tx_packets = stats->tx_unicast + stats->tx_broadcast +
		stats->tx_multicast;
	vf_stats->rx_bytes   = stats->rx_bytes;
	vf_stats->tx_bytes   = stats->tx_bytes;
	vf_stats->broadcast  = stats->rx_broadcast;
	vf_stats->multicast  = stats->rx_multicast;
	vf_stats->rx_dropped = stats->rx_discards;
	vf_stats->tx_dropped = stats->tx_discards;

out_put_vf:
	ice_put_vf(vf);
	return ret;
}

/**
 * ice_is_supported_port_vlan_proto - make sure the vlan_proto is supported
 * @hw: hardware structure used to check the VLAN mode
 * @vlan_proto: VLAN TPID being checked
 *
 * If the device is configured in Double VLAN Mode (DVM), then both ETH_P_8021Q
 * and ETH_P_8021AD are supported. If the device is configured in Single VLAN
 * Mode (SVM), then only ETH_P_8021Q is supported.
 */
static bool
ice_is_supported_port_vlan_proto(struct ice_hw *hw, u16 vlan_proto)
{
	bool is_supported = false;

	switch (vlan_proto) {
	case ETH_P_8021Q:
		is_supported = true;
		break;
	case ETH_P_8021AD:
		if (ice_is_dvm_ena(hw))
			is_supported = true;
		break;
	}

	return is_supported;
}

/**
 * ice_set_vf_port_vlan
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @vlan_id: VLAN ID being set
 * @qos: priority setting
 * @vlan_proto: VLAN protocol
 *
 * program VF Port VLAN ID and/or QoS
 */
int
ice_set_vf_port_vlan(struct net_device *netdev, int vf_id, u16 vlan_id, u8 qos,
		     __be16 vlan_proto)
{
	struct ice_pf *pf = ice_netdev_to_pf(netdev);
	u16 local_vlan_proto = ntohs(vlan_proto);
	struct device *dev;
	struct ice_vf *vf;
	int ret;

	dev = ice_pf_to_dev(pf);

	if (vlan_id >= VLAN_N_VID || qos > 7) {
		dev_err(dev, "Invalid Port VLAN parameters for VF %d, ID %d, QoS %d\n",
			vf_id, vlan_id, qos);
		return -EINVAL;
	}

	if (!ice_is_supported_port_vlan_proto(&pf->hw, local_vlan_proto)) {
		dev_err(dev, "VF VLAN protocol 0x%04x is not supported\n",
			local_vlan_proto);
		return -EPROTONOSUPPORT;
	}

	vf = ice_get_vf_by_id(pf, vf_id);
	if (!vf)
		return -EINVAL;

	ret = ice_check_vf_ready_for_cfg(vf);
	if (ret)
		goto out_put_vf;

	if (ice_vf_get_port_vlan_prio(vf) == qos &&
	    ice_vf_get_port_vlan_tpid(vf) == local_vlan_proto &&
	    ice_vf_get_port_vlan_id(vf) == vlan_id) {
		/* duplicate request, so just return success */
		dev_dbg(dev, "Duplicate port VLAN %u, QoS %u, TPID 0x%04x request\n",
			vlan_id, qos, local_vlan_proto);
		ret = 0;
		goto out_put_vf;
	}

	mutex_lock(&vf->cfg_lock);

	vf->port_vlan_info = ICE_VLAN(local_vlan_proto, vlan_id, qos);
	if (ice_vf_is_port_vlan_ena(vf))
		dev_info(dev, "Setting VLAN %u, QoS %u, TPID 0x%04x on VF %d\n",
			 vlan_id, qos, local_vlan_proto, vf_id);
	else
		dev_info(dev, "Clearing port VLAN on VF %d\n", vf_id);

	ice_reset_vf(vf, ICE_VF_RESET_NOTIFY);
	mutex_unlock(&vf->cfg_lock);

out_put_vf:
	ice_put_vf(vf);
	return ret;
}

/**
 * ice_print_vf_rx_mdd_event - print VF Rx malicious driver detect event
 * @vf: pointer to the VF structure
 */
void ice_print_vf_rx_mdd_event(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;
	struct device *dev;

	dev = ice_pf_to_dev(pf);

	dev_info(dev, "%d Rx Malicious Driver Detection events detected on PF %d VF %d MAC %pM. mdd-auto-reset-vfs=%s\n",
		 vf->mdd_rx_events.count, pf->hw.pf_id, vf->vf_id,
		 vf->dev_lan_addr,
		 test_bit(ICE_FLAG_MDD_AUTO_RESET_VF, pf->flags)
			  ? "on" : "off");
}

/**
 * ice_print_vf_tx_mdd_event - print VF Tx malicious driver detect event
 * @vf: pointer to the VF structure
 */
void ice_print_vf_tx_mdd_event(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;
	struct device *dev;

	dev = ice_pf_to_dev(pf);

	dev_info(dev, "%d Tx Malicious Driver Detection events detected on PF %d VF %d MAC %pM. mdd-auto-reset-vfs=%s\n",
		 vf->mdd_tx_events.count, pf->hw.pf_id, vf->vf_id,
		 vf->dev_lan_addr,
		 test_bit(ICE_FLAG_MDD_AUTO_RESET_VF, pf->flags)
			  ? "on" : "off");
}

/**
 * ice_print_vfs_mdd_events - print VFs malicious driver detect event
 * @pf: pointer to the PF structure
 *
 * Called from ice_handle_mdd_event to rate limit and print VFs MDD events.
 */
void ice_print_vfs_mdd_events(struct ice_pf *pf)
{
	struct ice_vf *vf;
	unsigned int bkt;

	/* check that there are pending MDD events to print */
	if (!test_and_clear_bit(ICE_MDD_VF_PRINT_PENDING, pf->state))
		return;

	/* VF MDD event logs are rate limited to one second intervals */
	if (time_is_after_jiffies(pf->vfs.last_printed_mdd_jiffies + HZ * 1))
		return;

	pf->vfs.last_printed_mdd_jiffies = jiffies;

	mutex_lock(&pf->vfs.table_lock);
	ice_for_each_vf(pf, bkt, vf) {
		/* only print Rx MDD event message if there are new events */
		if (vf->mdd_rx_events.count != vf->mdd_rx_events.last_printed) {
			vf->mdd_rx_events.last_printed =
							vf->mdd_rx_events.count;
			ice_print_vf_rx_mdd_event(vf);
		}

		/* only print Tx MDD event message if there are new events */
		if (vf->mdd_tx_events.count != vf->mdd_tx_events.last_printed) {
			vf->mdd_tx_events.last_printed =
							vf->mdd_tx_events.count;
			ice_print_vf_tx_mdd_event(vf);
		}
	}
	mutex_unlock(&pf->vfs.table_lock);
}

/**
 * ice_restore_all_vfs_msi_state - restore VF MSI state after PF FLR
 * @pf: pointer to the PF structure
 *
 * Called when recovering from a PF FLR to restore interrupt capability to
 * the VFs.
 */
void ice_restore_all_vfs_msi_state(struct ice_pf *pf)
{
	struct ice_vf *vf;
	u32 bkt;

	ice_for_each_vf(pf, bkt, vf)
		pci_restore_msi_state(vf->vfdev);
}
