// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2022, Intel Corporation. */

#include "ice.h"
#include "ice_lib.h"
#include "ice_trace.h"
#include <linux/dpll.h>

#define ICE_CGU_STATE_ACQ_ERR_THRESHOLD		50
#define ICE_DPLL_PIN_IDX_INVALID		0xff
#define ICE_DPLL_RCLK_NUM_PER_PF		1
#define ICE_DPLL_PIN_ESYNC_PULSE_HIGH_PERCENT	25
#define ICE_DPLL_PIN_GEN_RCLK_FREQ		1953125
#define ICE_DPLL_PIN_PRIO_OUTPUT		0xff
#define ICE_DPLL_INPUT_REF_NUM			10
#define ICE_DPLL_PHASE_OFFSET_PERIOD		2
#define ICE_DPLL_SW_PIN_INPUT_BASE_SFP		4
#define ICE_DPLL_SW_PIN_INPUT_BASE_QSFP		6
#define ICE_DPLL_SW_PIN_OUTPUT_BASE		0

#define ICE_DPLL_PIN_SW_INPUT_ABS(in_idx) \
	(ICE_DPLL_SW_PIN_INPUT_BASE_SFP + (in_idx))

#define ICE_DPLL_PIN_SW_1_INPUT_ABS_IDX \
	(ICE_DPLL_PIN_SW_INPUT_ABS(ICE_DPLL_PIN_SW_1_IDX))

#define ICE_DPLL_PIN_SW_2_INPUT_ABS_IDX \
	(ICE_DPLL_PIN_SW_INPUT_ABS(ICE_DPLL_PIN_SW_2_IDX))

#define ICE_DPLL_PIN_SW_OUTPUT_ABS(out_idx) \
	(ICE_DPLL_SW_PIN_OUTPUT_BASE + (out_idx))

#define ICE_DPLL_PIN_SW_1_OUTPUT_ABS_IDX \
	(ICE_DPLL_PIN_SW_OUTPUT_ABS(ICE_DPLL_PIN_SW_1_IDX))

#define ICE_DPLL_PIN_SW_2_OUTPUT_ABS_IDX \
	(ICE_DPLL_PIN_SW_OUTPUT_ABS(ICE_DPLL_PIN_SW_2_IDX))

#define ICE_SR_PFA_DPLL_DEFAULTS		0x152
#define ICE_DPLL_PFA_REF_SYNC_TYPE		0x2420
#define ICE_DPLL_PFA_REF_SYNC_TYPE2		0x2424
#define ICE_DPLL_PFA_END			0xFFFF
#define ICE_DPLL_PFA_HEADER_LEN			4
#define ICE_DPLL_PFA_ENTRY_LEN			3
#define ICE_DPLL_PFA_MAILBOX_REF_SYNC_PIN_S	4
#define ICE_DPLL_PFA_MASK_OFFSET		1
#define ICE_DPLL_PFA_VALUE_OFFSET		2

#define ICE_DPLL_E810C_SFP_NC_PINS		2
#define ICE_DPLL_E810C_SFP_NC_START		4

/**
 * enum ice_dpll_pin_type - enumerate ice pin types:
 * @ICE_DPLL_PIN_INVALID: invalid pin type
 * @ICE_DPLL_PIN_TYPE_INPUT: input pin
 * @ICE_DPLL_PIN_TYPE_OUTPUT: output pin
 * @ICE_DPLL_PIN_TYPE_RCLK_INPUT: recovery clock input pin
 * @ICE_DPLL_PIN_TYPE_SOFTWARE: software controlled SMA/U.FL pins
 */
enum ice_dpll_pin_type {
	ICE_DPLL_PIN_INVALID,
	ICE_DPLL_PIN_TYPE_INPUT,
	ICE_DPLL_PIN_TYPE_OUTPUT,
	ICE_DPLL_PIN_TYPE_RCLK_INPUT,
	ICE_DPLL_PIN_TYPE_SOFTWARE,
};

static const char * const pin_type_name[] = {
	[ICE_DPLL_PIN_TYPE_INPUT] = "input",
	[ICE_DPLL_PIN_TYPE_OUTPUT] = "output",
	[ICE_DPLL_PIN_TYPE_RCLK_INPUT] = "rclk-input",
	[ICE_DPLL_PIN_TYPE_SOFTWARE] = "software",
};

static const char * const ice_dpll_sw_pin_sma[] = { "SMA1", "SMA2" };
static const char * const ice_dpll_sw_pin_ufl[] = { "U.FL1", "U.FL2" };

static const struct dpll_pin_frequency ice_esync_range[] = {
	DPLL_PIN_FREQUENCY_RANGE(0, DPLL_PIN_FREQUENCY_1_HZ),
};

/**
 * ice_dpll_is_sw_pin - check if given pin shall be controlled by SW
 * @pf: private board structure
 * @index: index of a pin as understood by FW
 * @input: true for input, false for output
 *
 * Check if the pin shall be controlled by SW - instead of providing raw access
 * for pin control. For E810 NIC with dpll there is additional MUX-related logic
 * between SMA/U.FL pins/connectors and dpll device, best to give user access
 * with series of wrapper functions as from user perspective they convey single
 * functionality rather then separated pins.
 *
 * Return:
 * * true - pin controlled by SW
 * * false - pin not controlled by SW
 */
static bool ice_dpll_is_sw_pin(struct ice_pf *pf, u8 index, bool input)
{
	if (input && pf->hw.device_id == ICE_DEV_ID_E810C_QSFP)
		index -= ICE_DPLL_SW_PIN_INPUT_BASE_QSFP -
			 ICE_DPLL_SW_PIN_INPUT_BASE_SFP;

	if ((input && (index == ICE_DPLL_PIN_SW_1_INPUT_ABS_IDX ||
		       index == ICE_DPLL_PIN_SW_2_INPUT_ABS_IDX)) ||
	    (!input && (index == ICE_DPLL_PIN_SW_1_OUTPUT_ABS_IDX ||
			index == ICE_DPLL_PIN_SW_2_OUTPUT_ABS_IDX)))
		return true;
	return false;
}

/**
 * ice_dpll_is_reset - check if reset is in progress
 * @pf: private board structure
 * @extack: error reporting
 *
 * If reset is in progress, fill extack with error.
 *
 * Return:
 * * false - no reset in progress
 * * true - reset in progress
 */
static bool ice_dpll_is_reset(struct ice_pf *pf, struct netlink_ext_ack *extack)
{
	if (ice_is_reset_in_progress(pf->state)) {
		NL_SET_ERR_MSG(extack, "PF reset in progress");
		return true;
	}
	return false;
}

/**
 * ice_dpll_pin_freq_set - set pin's frequency
 * @pf: private board structure
 * @pin: pointer to a pin
 * @pin_type: type of pin being configured
 * @freq: frequency to be set
 * @extack: error reporting
 *
 * Set requested frequency on a pin.
 *
 * Context: Called under pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error on AQ or wrong pin type given
 */
static int
ice_dpll_pin_freq_set(struct ice_pf *pf, struct ice_dpll_pin *pin,
		      enum ice_dpll_pin_type pin_type, const u32 freq,
		      struct netlink_ext_ack *extack)
{
	u8 flags;
	int ret;

	switch (pin_type) {
	case ICE_DPLL_PIN_TYPE_INPUT:
		flags = ICE_AQC_SET_CGU_IN_CFG_FLG1_UPDATE_FREQ;
		ret = ice_aq_set_input_pin_cfg(&pf->hw, pin->idx, flags,
					       pin->flags[0], freq, 0);
		break;
	case ICE_DPLL_PIN_TYPE_OUTPUT:
		flags = ICE_AQC_SET_CGU_OUT_CFG_UPDATE_FREQ;
		ret = ice_aq_set_output_pin_cfg(&pf->hw, pin->idx, flags,
						0, freq, 0);
		break;
	default:
		return -EINVAL;
	}
	if (ret) {
		NL_SET_ERR_MSG_FMT(extack,
				   "err:%d %s failed to set pin freq:%u on pin:%u",
				   ret,
				   libie_aq_str(pf->hw.adminq.sq_last_status),
				   freq, pin->idx);
		return ret;
	}
	pin->freq = freq;

	return 0;
}

/**
 * ice_dpll_frequency_set - wrapper for pin callback for set frequency
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: pointer to dpll
 * @dpll_priv: private data pointer passed on dpll registration
 * @frequency: frequency to be set
 * @extack: error reporting
 * @pin_type: type of pin being configured
 *
 * Wraps internal set frequency command on a pin.
 *
 * Context: Acquires pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error pin not found or couldn't set in hw
 */
static int
ice_dpll_frequency_set(const struct dpll_pin *pin, void *pin_priv,
		       const struct dpll_device *dpll, void *dpll_priv,
		       const u32 frequency,
		       struct netlink_ext_ack *extack,
		       enum ice_dpll_pin_type pin_type)
{
	struct ice_dpll_pin *p = pin_priv;
	struct ice_dpll *d = dpll_priv;
	struct ice_pf *pf = d->pf;
	int ret;

	if (ice_dpll_is_reset(pf, extack))
		return -EBUSY;

	mutex_lock(&pf->dplls.lock);
	ret = ice_dpll_pin_freq_set(pf, p, pin_type, frequency, extack);
	mutex_unlock(&pf->dplls.lock);

	return ret;
}

/**
 * ice_dpll_input_frequency_set - input pin callback for set frequency
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: pointer to dpll
 * @dpll_priv: private data pointer passed on dpll registration
 * @frequency: frequency to be set
 * @extack: error reporting
 *
 * Wraps internal set frequency command on a pin.
 *
 * Context: Calls a function which acquires pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error pin not found or couldn't set in hw
 */
static int
ice_dpll_input_frequency_set(const struct dpll_pin *pin, void *pin_priv,
			     const struct dpll_device *dpll, void *dpll_priv,
			     u64 frequency, struct netlink_ext_ack *extack)
{
	return ice_dpll_frequency_set(pin, pin_priv, dpll, dpll_priv, frequency,
				      extack, ICE_DPLL_PIN_TYPE_INPUT);
}

/**
 * ice_dpll_output_frequency_set - output pin callback for set frequency
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: pointer to dpll
 * @dpll_priv: private data pointer passed on dpll registration
 * @frequency: frequency to be set
 * @extack: error reporting
 *
 * Wraps internal set frequency command on a pin.
 *
 * Context: Calls a function which acquires pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error pin not found or couldn't set in hw
 */
static int
ice_dpll_output_frequency_set(const struct dpll_pin *pin, void *pin_priv,
			      const struct dpll_device *dpll, void *dpll_priv,
			      u64 frequency, struct netlink_ext_ack *extack)
{
	return ice_dpll_frequency_set(pin, pin_priv, dpll, dpll_priv, frequency,
				      extack, ICE_DPLL_PIN_TYPE_OUTPUT);
}

/**
 * ice_dpll_frequency_get - wrapper for pin callback for get frequency
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: pointer to dpll
 * @dpll_priv: private data pointer passed on dpll registration
 * @frequency: on success holds pin's frequency
 * @extack: error reporting
 * @pin_type: type of pin being configured
 *
 * Wraps internal get frequency command of a pin.
 *
 * Context: Acquires pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error pin not found or couldn't get from hw
 */
static int
ice_dpll_frequency_get(const struct dpll_pin *pin, void *pin_priv,
		       const struct dpll_device *dpll, void *dpll_priv,
		       u64 *frequency, struct netlink_ext_ack *extack,
		       enum ice_dpll_pin_type pin_type)
{
	struct ice_dpll_pin *p = pin_priv;
	struct ice_dpll *d = dpll_priv;
	struct ice_pf *pf = d->pf;

	mutex_lock(&pf->dplls.lock);
	*frequency = p->freq;
	mutex_unlock(&pf->dplls.lock);

	return 0;
}

/**
 * ice_dpll_input_frequency_get - input pin callback for get frequency
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: pointer to dpll
 * @dpll_priv: private data pointer passed on dpll registration
 * @frequency: on success holds pin's frequency
 * @extack: error reporting
 *
 * Wraps internal get frequency command of a input pin.
 *
 * Context: Calls a function which acquires pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error pin not found or couldn't get from hw
 */
static int
ice_dpll_input_frequency_get(const struct dpll_pin *pin, void *pin_priv,
			     const struct dpll_device *dpll, void *dpll_priv,
			     u64 *frequency, struct netlink_ext_ack *extack)
{
	return ice_dpll_frequency_get(pin, pin_priv, dpll, dpll_priv, frequency,
				      extack, ICE_DPLL_PIN_TYPE_INPUT);
}

/**
 * ice_dpll_output_frequency_get - output pin callback for get frequency
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: pointer to dpll
 * @dpll_priv: private data pointer passed on dpll registration
 * @frequency: on success holds pin's frequency
 * @extack: error reporting
 *
 * Wraps internal get frequency command of a pin.
 *
 * Context: Calls a function which acquires pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error pin not found or couldn't get from hw
 */
static int
ice_dpll_output_frequency_get(const struct dpll_pin *pin, void *pin_priv,
			      const struct dpll_device *dpll, void *dpll_priv,
			      u64 *frequency, struct netlink_ext_ack *extack)
{
	return ice_dpll_frequency_get(pin, pin_priv, dpll, dpll_priv, frequency,
				      extack, ICE_DPLL_PIN_TYPE_OUTPUT);
}

/**
 * ice_dpll_sw_pin_frequency_set - callback to set frequency of SW pin
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: pointer to dpll
 * @dpll_priv: private data pointer passed on dpll registration
 * @frequency: on success holds pin's frequency
 * @extack: error reporting
 *
 * Calls set frequency command for corresponding and active input/output pin.
 *
 * Context: Calls a function which acquires and releases pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error pin not active or couldn't get from hw
 */
static int
ice_dpll_sw_pin_frequency_set(const struct dpll_pin *pin, void *pin_priv,
			      const struct dpll_device *dpll, void *dpll_priv,
			      u64 frequency, struct netlink_ext_ack *extack)
{
	struct ice_dpll_pin *sma = pin_priv;
	int ret;

	if (!sma->active) {
		NL_SET_ERR_MSG(extack, "pin is not active");
		return -EINVAL;
	}
	if (sma->direction == DPLL_PIN_DIRECTION_INPUT)
		ret = ice_dpll_input_frequency_set(NULL, sma->input, dpll,
						   dpll_priv, frequency,
						   extack);
	else
		ret = ice_dpll_output_frequency_set(NULL, sma->output, dpll,
						    dpll_priv, frequency,
						    extack);

	return ret;
}

/**
 * ice_dpll_sw_pin_frequency_get - callback for get frequency of SW pin
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: pointer to dpll
 * @dpll_priv: private data pointer passed on dpll registration
 * @frequency: on success holds pin's frequency
 * @extack: error reporting
 *
 * Calls get frequency command for corresponding active input/output.
 *
 * Context: Calls a function which acquires and releases pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error pin not active or couldn't get from hw
 */
static int
ice_dpll_sw_pin_frequency_get(const struct dpll_pin *pin, void *pin_priv,
			      const struct dpll_device *dpll, void *dpll_priv,
			      u64 *frequency, struct netlink_ext_ack *extack)
{
	struct ice_dpll_pin *sma = pin_priv;
	int ret;

	if (!sma->active) {
		*frequency = 0;
		return 0;
	}
	if (sma->direction == DPLL_PIN_DIRECTION_INPUT) {
		ret = ice_dpll_input_frequency_get(NULL, sma->input, dpll,
						   dpll_priv, frequency,
						   extack);
	} else {
		ret = ice_dpll_output_frequency_get(NULL, sma->output, dpll,
						    dpll_priv, frequency,
						    extack);
	}

	return ret;
}

/**
 * ice_dpll_pin_enable - enable a pin on dplls
 * @hw: board private hw structure
 * @pin: pointer to a pin
 * @dpll_idx: dpll index to connect to output pin
 * @pin_type: type of pin being enabled
 * @extack: error reporting
 *
 * Enable a pin on both dplls. Store current state in pin->flags.
 *
 * Context: Called under pf->dplls.lock
 * Return:
 * * 0 - OK
 * * negative - error
 */
static int
ice_dpll_pin_enable(struct ice_hw *hw, struct ice_dpll_pin *pin,
		    u8 dpll_idx, enum ice_dpll_pin_type pin_type,
		    struct netlink_ext_ack *extack)
{
	u8 flags = 0;
	int ret;

	switch (pin_type) {
	case ICE_DPLL_PIN_TYPE_INPUT:
		if (pin->flags[0] & ICE_AQC_GET_CGU_IN_CFG_FLG2_ESYNC_EN)
			flags |= ICE_AQC_SET_CGU_IN_CFG_FLG2_ESYNC_EN;
		flags |= ICE_AQC_SET_CGU_IN_CFG_FLG2_INPUT_EN;
		ret = ice_aq_set_input_pin_cfg(hw, pin->idx, 0, flags, 0, 0);
		break;
	case ICE_DPLL_PIN_TYPE_OUTPUT:
		flags = ICE_AQC_SET_CGU_OUT_CFG_UPDATE_SRC_SEL;
		if (pin->flags[0] & ICE_AQC_GET_CGU_OUT_CFG_ESYNC_EN)
			flags |= ICE_AQC_SET_CGU_OUT_CFG_ESYNC_EN;
		flags |= ICE_AQC_SET_CGU_OUT_CFG_OUT_EN;
		ret = ice_aq_set_output_pin_cfg(hw, pin->idx, flags, dpll_idx,
						0, 0);
		break;
	default:
		return -EINVAL;
	}
	if (ret)
		NL_SET_ERR_MSG_FMT(extack,
				   "err:%d %s failed to enable %s pin:%u",
				   ret, libie_aq_str(hw->adminq.sq_last_status),
				   pin_type_name[pin_type], pin->idx);

	return ret;
}

/**
 * ice_dpll_pin_disable - disable a pin on dplls
 * @hw: board private hw structure
 * @pin: pointer to a pin
 * @pin_type: type of pin being disabled
 * @extack: error reporting
 *
 * Disable a pin on both dplls. Store current state in pin->flags.
 *
 * Context: Called under pf->dplls.lock
 * Return:
 * * 0 - OK
 * * negative - error
 */
static int
ice_dpll_pin_disable(struct ice_hw *hw, struct ice_dpll_pin *pin,
		     enum ice_dpll_pin_type pin_type,
		     struct netlink_ext_ack *extack)
{
	u8 flags = 0;
	int ret;

	switch (pin_type) {
	case ICE_DPLL_PIN_TYPE_INPUT:
		if (pin->flags[0] & ICE_AQC_GET_CGU_IN_CFG_FLG2_ESYNC_EN)
			flags |= ICE_AQC_SET_CGU_IN_CFG_FLG2_ESYNC_EN;
		ret = ice_aq_set_input_pin_cfg(hw, pin->idx, 0, flags, 0, 0);
		break;
	case ICE_DPLL_PIN_TYPE_OUTPUT:
		if (pin->flags[0] & ICE_AQC_GET_CGU_OUT_CFG_ESYNC_EN)
			flags |= ICE_AQC_SET_CGU_OUT_CFG_ESYNC_EN;
		ret = ice_aq_set_output_pin_cfg(hw, pin->idx, flags, 0, 0, 0);
		break;
	default:
		return -EINVAL;
	}
	if (ret)
		NL_SET_ERR_MSG_FMT(extack,
				   "err:%d %s failed to disable %s pin:%u",
				   ret, libie_aq_str(hw->adminq.sq_last_status),
				   pin_type_name[pin_type], pin->idx);

	return ret;
}

/**
 * ice_dpll_sw_pins_update - update status of all SW pins
 * @pf: private board struct
 *
 * Determine and update pin struct fields (direction/active) of their current
 * values for all the SW controlled pins.
 *
 * Context: Call with pf->dplls.lock held
 * Return:
 * * 0 - OK
 * * negative - error
 */
static int
ice_dpll_sw_pins_update(struct ice_pf *pf)
{
	struct ice_dplls *d = &pf->dplls;
	struct ice_dpll_pin *p;
	u8 data = 0;
	int ret;

	ret = ice_read_sma_ctrl(&pf->hw, &data);
	if (ret)
		return ret;
	/* no change since last check */
	if (d->sma_data == data)
		return 0;

	/*
	 * SMA1/U.FL1 vs SMA2/U.FL2 are using different bit scheme to decide
	 * on their direction and if are active
	 */
	p = &d->sma[ICE_DPLL_PIN_SW_1_IDX];
	p->active = true;
	p->direction = DPLL_PIN_DIRECTION_INPUT;
	if (data & ICE_SMA1_DIR_EN) {
		p->direction = DPLL_PIN_DIRECTION_OUTPUT;
		if (data & ICE_SMA1_TX_EN)
			p->active = false;
	}

	p = &d->sma[ICE_DPLL_PIN_SW_2_IDX];
	p->active = true;
	p->direction = DPLL_PIN_DIRECTION_INPUT;
	if ((data & ICE_SMA2_INACTIVE_MASK) == ICE_SMA2_INACTIVE_MASK)
		p->active = false;
	else if (data & ICE_SMA2_DIR_EN)
		p->direction = DPLL_PIN_DIRECTION_OUTPUT;

	p = &d->ufl[ICE_DPLL_PIN_SW_1_IDX];
	if (!(data & (ICE_SMA1_DIR_EN | ICE_SMA1_TX_EN)))
		p->active = true;
	else
		p->active = false;

	p = &d->ufl[ICE_DPLL_PIN_SW_2_IDX];
	p->active = (data & ICE_SMA2_DIR_EN) && !(data & ICE_SMA2_UFL2_RX_DIS);
	d->sma_data = data;

	return 0;
}

/**
 * ice_dpll_pin_state_update - update pin's state
 * @pf: private board struct
 * @pin: structure with pin attributes to be updated
 * @pin_type: type of pin being updated
 * @extack: error reporting
 *
 * Determine pin current state and frequency, then update struct
 * holding the pin info. For input pin states are separated for each
 * dpll, for rclk pins states are separated for each parent.
 *
 * Context: Called under pf->dplls.lock
 * Return:
 * * 0 - OK
 * * negative - error
 */
static int
ice_dpll_pin_state_update(struct ice_pf *pf, struct ice_dpll_pin *pin,
			  enum ice_dpll_pin_type pin_type,
			  struct netlink_ext_ack *extack)
{
	u8 parent, port_num = ICE_AQC_SET_PHY_REC_CLK_OUT_CURR_PORT;
	int ret;

	switch (pin_type) {
	case ICE_DPLL_PIN_TYPE_INPUT:
		ret = ice_aq_get_input_pin_cfg(&pf->hw, pin->idx, &pin->status,
					       NULL, NULL, &pin->flags[0],
					       &pin->freq, &pin->phase_adjust);
		if (ret)
			goto err;
		if (ICE_AQC_GET_CGU_IN_CFG_FLG2_INPUT_EN & pin->flags[0]) {
			if (pin->pin) {
				pin->state[pf->dplls.eec.dpll_idx] =
					pin->pin == pf->dplls.eec.active_input ?
					DPLL_PIN_STATE_CONNECTED :
					DPLL_PIN_STATE_SELECTABLE;
				pin->state[pf->dplls.pps.dpll_idx] =
					pin->pin == pf->dplls.pps.active_input ?
					DPLL_PIN_STATE_CONNECTED :
					DPLL_PIN_STATE_SELECTABLE;
			} else {
				pin->state[pf->dplls.eec.dpll_idx] =
					DPLL_PIN_STATE_SELECTABLE;
				pin->state[pf->dplls.pps.dpll_idx] =
					DPLL_PIN_STATE_SELECTABLE;
			}
		} else {
			pin->state[pf->dplls.eec.dpll_idx] =
				DPLL_PIN_STATE_DISCONNECTED;
			pin->state[pf->dplls.pps.dpll_idx] =
				DPLL_PIN_STATE_DISCONNECTED;
		}
		break;
	case ICE_DPLL_PIN_TYPE_OUTPUT:
		ret = ice_aq_get_output_pin_cfg(&pf->hw, pin->idx,
						&pin->flags[0], &parent,
						&pin->freq, NULL);
		if (ret)
			goto err;

		parent &= ICE_AQC_GET_CGU_OUT_CFG_DPLL_SRC_SEL;
		if (ICE_AQC_GET_CGU_OUT_CFG_OUT_EN & pin->flags[0]) {
			pin->state[pf->dplls.eec.dpll_idx] =
				parent == pf->dplls.eec.dpll_idx ?
				DPLL_PIN_STATE_CONNECTED :
				DPLL_PIN_STATE_DISCONNECTED;
			pin->state[pf->dplls.pps.dpll_idx] =
				parent == pf->dplls.pps.dpll_idx ?
				DPLL_PIN_STATE_CONNECTED :
				DPLL_PIN_STATE_DISCONNECTED;
		} else {
			pin->state[pf->dplls.eec.dpll_idx] =
				DPLL_PIN_STATE_DISCONNECTED;
			pin->state[pf->dplls.pps.dpll_idx] =
				DPLL_PIN_STATE_DISCONNECTED;
		}
		break;
	case ICE_DPLL_PIN_TYPE_RCLK_INPUT:
		for (parent = 0; parent < pf->dplls.rclk.num_parents;
		     parent++) {
			u8 p = parent;

			ret = ice_aq_get_phy_rec_clk_out(&pf->hw, &p,
							 &port_num,
							 &pin->flags[parent],
							 NULL);
			if (ret)
				goto err;
			if (ICE_AQC_GET_PHY_REC_CLK_OUT_OUT_EN &
			    pin->flags[parent])
				pin->state[parent] = DPLL_PIN_STATE_CONNECTED;
			else
				pin->state[parent] =
					DPLL_PIN_STATE_DISCONNECTED;
		}
		break;
	case ICE_DPLL_PIN_TYPE_SOFTWARE:
		ret = ice_dpll_sw_pins_update(pf);
		if (ret)
			goto err;
		break;
	default:
		return -EINVAL;
	}

	return 0;
err:
	if (extack)
		NL_SET_ERR_MSG_FMT(extack,
				   "err:%d %s failed to update %s pin:%u",
				   ret,
				   libie_aq_str(pf->hw.adminq.sq_last_status),
				   pin_type_name[pin_type], pin->idx);
	else
		dev_err_ratelimited(ice_pf_to_dev(pf),
				    "err:%d %s failed to update %s pin:%u\n",
				    ret,
				    libie_aq_str(pf->hw.adminq.sq_last_status),
				    pin_type_name[pin_type], pin->idx);
	return ret;
}

/**
 * ice_dpll_hw_input_prio_set - set input priority value in hardware
 * @pf: board private structure
 * @dpll: ice dpll pointer
 * @pin: ice pin pointer
 * @prio: priority value being set on a dpll
 * @extack: error reporting
 *
 * Internal wrapper for setting the priority in the hardware.
 *
 * Context: Called under pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - failure
 */
static int
ice_dpll_hw_input_prio_set(struct ice_pf *pf, struct ice_dpll *dpll,
			   struct ice_dpll_pin *pin, const u32 prio,
			   struct netlink_ext_ack *extack)
{
	int ret;

	ret = ice_aq_set_cgu_ref_prio(&pf->hw, dpll->dpll_idx, pin->idx,
				      (u8)prio);
	if (ret)
		NL_SET_ERR_MSG_FMT(extack,
				   "err:%d %s failed to set pin prio:%u on pin:%u",
				   ret,
				   libie_aq_str(pf->hw.adminq.sq_last_status),
				   prio, pin->idx);
	else
		dpll->input_prio[pin->idx] = prio;

	return ret;
}

/**
 * ice_dpll_lock_status_get - get dpll lock status callback
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @status: on success holds dpll's lock status
 * @status_error: status error value
 * @extack: error reporting
 *
 * Dpll subsystem callback, provides dpll's lock status.
 *
 * Context: Acquires pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - failure
 */
static int
ice_dpll_lock_status_get(const struct dpll_device *dpll, void *dpll_priv,
			 enum dpll_lock_status *status,
			 enum dpll_lock_status_error *status_error,
			 struct netlink_ext_ack *extack)
{
	struct ice_dpll *d = dpll_priv;
	struct ice_pf *pf = d->pf;

	mutex_lock(&pf->dplls.lock);
	*status = d->dpll_state;
	mutex_unlock(&pf->dplls.lock);

	return 0;
}

/**
 * ice_dpll_mode_get - get dpll's working mode
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @mode: on success holds current working mode of dpll
 * @extack: error reporting
 *
 * Dpll subsystem callback. Provides working mode of dpll.
 *
 * Context: Acquires pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - failure
 */
static int ice_dpll_mode_get(const struct dpll_device *dpll, void *dpll_priv,
			     enum dpll_mode *mode,
			     struct netlink_ext_ack *extack)
{
	struct ice_dpll *d = dpll_priv;
	struct ice_pf *pf = d->pf;

	mutex_lock(&pf->dplls.lock);
	*mode = d->mode;
	mutex_unlock(&pf->dplls.lock);

	return 0;
}

/**
 * ice_dpll_phase_offset_monitor_set - set phase offset monitor state
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @state: feature state to be set
 * @extack: error reporting
 *
 * Dpll subsystem callback. Enable/disable phase offset monitor feature of dpll.
 *
 * Context: Acquires and releases pf->dplls.lock
 * Return: 0 - success
 */
static int ice_dpll_phase_offset_monitor_set(const struct dpll_device *dpll,
					     void *dpll_priv,
					     enum dpll_feature_state state,
					     struct netlink_ext_ack *extack)
{
	struct ice_dpll *d = dpll_priv;
	struct ice_pf *pf = d->pf;

	mutex_lock(&pf->dplls.lock);
	if (state == DPLL_FEATURE_STATE_ENABLE)
		d->phase_offset_monitor_period = ICE_DPLL_PHASE_OFFSET_PERIOD;
	else
		d->phase_offset_monitor_period = 0;
	mutex_unlock(&pf->dplls.lock);

	return 0;
}

/**
 * ice_dpll_phase_offset_monitor_get - get phase offset monitor state
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @state: on success holds current state of phase offset monitor
 * @extack: error reporting
 *
 * Dpll subsystem callback. Provides current state of phase offset monitor
 * features on dpll device.
 *
 * Context: Acquires and releases pf->dplls.lock
 * Return: 0 - success
 */
static int ice_dpll_phase_offset_monitor_get(const struct dpll_device *dpll,
					     void *dpll_priv,
					     enum dpll_feature_state *state,
					     struct netlink_ext_ack *extack)
{
	struct ice_dpll *d = dpll_priv;
	struct ice_pf *pf = d->pf;

	mutex_lock(&pf->dplls.lock);
	if (d->phase_offset_monitor_period)
		*state = DPLL_FEATURE_STATE_ENABLE;
	else
		*state = DPLL_FEATURE_STATE_DISABLE;
	mutex_unlock(&pf->dplls.lock);

	return 0;
}

/**
 * ice_dpll_pin_state_set - set pin's state on dpll
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @enable: if pin shalll be enabled
 * @extack: error reporting
 * @pin_type: type of a pin
 *
 * Set pin state on a pin.
 *
 * Context: Acquires pf->dplls.lock
 * Return:
 * * 0 - OK or no change required
 * * negative - error
 */
static int
ice_dpll_pin_state_set(const struct dpll_pin *pin, void *pin_priv,
		       const struct dpll_device *dpll, void *dpll_priv,
		       bool enable, struct netlink_ext_ack *extack,
		       enum ice_dpll_pin_type pin_type)
{
	struct ice_dpll_pin *p = pin_priv;
	struct ice_dpll *d = dpll_priv;
	struct ice_pf *pf = d->pf;
	int ret;

	if (ice_dpll_is_reset(pf, extack))
		return -EBUSY;

	mutex_lock(&pf->dplls.lock);
	if (enable)
		ret = ice_dpll_pin_enable(&pf->hw, p, d->dpll_idx, pin_type,
					  extack);
	else
		ret = ice_dpll_pin_disable(&pf->hw, p, pin_type, extack);
	if (!ret)
		ret = ice_dpll_pin_state_update(pf, p, pin_type, extack);
	mutex_unlock(&pf->dplls.lock);

	return ret;
}

/**
 * ice_dpll_output_state_set - enable/disable output pin on dpll device
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: dpll being configured
 * @dpll_priv: private data pointer passed on dpll registration
 * @state: state of pin to be set
 * @extack: error reporting
 *
 * Dpll subsystem callback. Set given state on output type pin.
 *
 * Context: Calls a function which acquires pf->dplls.lock
 * Return:
 * * 0 - successfully enabled mode
 * * negative - failed to enable mode
 */
static int
ice_dpll_output_state_set(const struct dpll_pin *pin, void *pin_priv,
			  const struct dpll_device *dpll, void *dpll_priv,
			  enum dpll_pin_state state,
			  struct netlink_ext_ack *extack)
{
	bool enable = state == DPLL_PIN_STATE_CONNECTED;
	struct ice_dpll_pin *p = pin_priv;
	struct ice_dpll *d = dpll_priv;

	if (state == DPLL_PIN_STATE_SELECTABLE)
		return -EINVAL;
	if (!enable && p->state[d->dpll_idx] == DPLL_PIN_STATE_DISCONNECTED)
		return 0;

	return ice_dpll_pin_state_set(pin, pin_priv, dpll, dpll_priv, enable,
				      extack, ICE_DPLL_PIN_TYPE_OUTPUT);
}

/**
 * ice_dpll_input_state_set - enable/disable input pin on dpll levice
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: dpll being configured
 * @dpll_priv: private data pointer passed on dpll registration
 * @state: state of pin to be set
 * @extack: error reporting
 *
 * Dpll subsystem callback. Enables given mode on input type pin.
 *
 * Context: Calls a function which acquires pf->dplls.lock
 * Return:
 * * 0 - successfully enabled mode
 * * negative - failed to enable mode
 */
static int
ice_dpll_input_state_set(const struct dpll_pin *pin, void *pin_priv,
			 const struct dpll_device *dpll, void *dpll_priv,
			 enum dpll_pin_state state,
			 struct netlink_ext_ack *extack)
{
	bool enable = state == DPLL_PIN_STATE_SELECTABLE;

	return ice_dpll_pin_state_set(pin, pin_priv, dpll, dpll_priv, enable,
				      extack, ICE_DPLL_PIN_TYPE_INPUT);
}

/**
 * ice_dpll_pin_state_get - set pin's state on dpll
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @state: on success holds state of the pin
 * @extack: error reporting
 * @pin_type: type of questioned pin
 *
 * Determine pin state set it on a pin.
 *
 * Context: Acquires pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - failed to get state
 */
static int
ice_dpll_pin_state_get(const struct dpll_pin *pin, void *pin_priv,
		       const struct dpll_device *dpll, void *dpll_priv,
		       enum dpll_pin_state *state,
		       struct netlink_ext_ack *extack,
		       enum ice_dpll_pin_type pin_type)
{
	struct ice_dpll_pin *p = pin_priv;
	struct ice_dpll *d = dpll_priv;
	struct ice_pf *pf = d->pf;
	int ret;

	if (ice_dpll_is_reset(pf, extack))
		return -EBUSY;

	mutex_lock(&pf->dplls.lock);
	ret = ice_dpll_pin_state_update(pf, p, pin_type, extack);
	if (ret)
		goto unlock;
	if (pin_type == ICE_DPLL_PIN_TYPE_INPUT ||
	    pin_type == ICE_DPLL_PIN_TYPE_OUTPUT)
		*state = p->state[d->dpll_idx];
	ret = 0;
unlock:
	mutex_unlock(&pf->dplls.lock);

	return ret;
}

/**
 * ice_dpll_output_state_get - get output pin state on dpll device
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @state: on success holds state of the pin
 * @extack: error reporting
 *
 * Dpll subsystem callback. Check state of a pin.
 *
 * Context: Calls a function which acquires pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - failed to get state
 */
static int
ice_dpll_output_state_get(const struct dpll_pin *pin, void *pin_priv,
			  const struct dpll_device *dpll, void *dpll_priv,
			  enum dpll_pin_state *state,
			  struct netlink_ext_ack *extack)
{
	return ice_dpll_pin_state_get(pin, pin_priv, dpll, dpll_priv, state,
				      extack, ICE_DPLL_PIN_TYPE_OUTPUT);
}

/**
 * ice_dpll_input_state_get - get input pin state on dpll device
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @state: on success holds state of the pin
 * @extack: error reporting
 *
 * Dpll subsystem callback. Check state of a input pin.
 *
 * Context: Calls a function which acquires pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - failed to get state
 */
static int
ice_dpll_input_state_get(const struct dpll_pin *pin, void *pin_priv,
			 const struct dpll_device *dpll, void *dpll_priv,
			 enum dpll_pin_state *state,
			 struct netlink_ext_ack *extack)
{
	return ice_dpll_pin_state_get(pin, pin_priv, dpll, dpll_priv, state,
				      extack, ICE_DPLL_PIN_TYPE_INPUT);
}

/**
 * ice_dpll_sma_direction_set - set direction of SMA pin
 * @p: pointer to a pin
 * @direction: requested direction of the pin
 * @extack: error reporting
 *
 * Wrapper for dpll subsystem callback. Set direction of a SMA pin.
 *
 * Context: Call with pf->dplls.lock held
 * Return:
 * * 0 - success
 * * negative - failed to get state
 */
static int ice_dpll_sma_direction_set(struct ice_dpll_pin *p,
				      enum dpll_pin_direction direction,
				      struct netlink_ext_ack *extack)
{
	u8 data;
	int ret;

	if (p->direction == direction && p->active)
		return 0;
	ret = ice_read_sma_ctrl(&p->pf->hw, &data);
	if (ret)
		return ret;

	switch (p->idx) {
	case ICE_DPLL_PIN_SW_1_IDX:
		data &= ~ICE_SMA1_MASK;
		if (direction == DPLL_PIN_DIRECTION_OUTPUT)
			data |= ICE_SMA1_DIR_EN;
		break;
	case ICE_DPLL_PIN_SW_2_IDX:
		if (direction == DPLL_PIN_DIRECTION_INPUT) {
			data &= ~ICE_SMA2_DIR_EN;
		} else {
			data &= ~ICE_SMA2_TX_EN;
			data |= ICE_SMA2_DIR_EN;
		}
		break;
	default:
		return -EINVAL;
	}
	ret = ice_write_sma_ctrl(&p->pf->hw, data);
	if (!ret)
		ret = ice_dpll_pin_state_update(p->pf, p,
						ICE_DPLL_PIN_TYPE_SOFTWARE,
						extack);

	return ret;
}

/**
 * ice_dpll_ufl_pin_state_set - set U.FL pin state on dpll device
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @state: requested state of the pin
 * @extack: error reporting
 *
 * Dpll subsystem callback. Set the state of a pin.
 *
 * Context: Acquires and releases pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error
 */
static int
ice_dpll_ufl_pin_state_set(const struct dpll_pin *pin, void *pin_priv,
			   const struct dpll_device *dpll, void *dpll_priv,
			   enum dpll_pin_state state,
			   struct netlink_ext_ack *extack)
{
	struct ice_dpll_pin *p = pin_priv, *target;
	struct ice_dpll *d = dpll_priv;
	enum ice_dpll_pin_type type;
	struct ice_pf *pf = p->pf;
	struct ice_hw *hw;
	bool enable;
	u8 data;
	int ret;

	if (ice_dpll_is_reset(pf, extack))
		return -EBUSY;

	mutex_lock(&pf->dplls.lock);
	hw = &pf->hw;
	ret = ice_read_sma_ctrl(hw, &data);
	if (ret)
		goto unlock;

	ret = -EINVAL;
	switch (p->idx) {
	case ICE_DPLL_PIN_SW_1_IDX:
		if (state == DPLL_PIN_STATE_CONNECTED) {
			data &= ~ICE_SMA1_MASK;
			enable = true;
		} else if (state == DPLL_PIN_STATE_DISCONNECTED) {
			data |= ICE_SMA1_TX_EN;
			enable = false;
		} else {
			goto unlock;
		}
		target = p->output;
		type = ICE_DPLL_PIN_TYPE_OUTPUT;
		break;
	case ICE_DPLL_PIN_SW_2_IDX:
		if (state == DPLL_PIN_STATE_SELECTABLE) {
			data |= ICE_SMA2_DIR_EN;
			data &= ~ICE_SMA2_UFL2_RX_DIS;
			enable = true;
		} else if (state == DPLL_PIN_STATE_DISCONNECTED) {
			data |= ICE_SMA2_UFL2_RX_DIS;
			enable = false;
		} else {
			goto unlock;
		}
		target = p->input;
		type = ICE_DPLL_PIN_TYPE_INPUT;
		break;
	default:
		goto unlock;
	}

	ret = ice_write_sma_ctrl(hw, data);
	if (ret)
		goto unlock;
	ret = ice_dpll_pin_state_update(pf, p, ICE_DPLL_PIN_TYPE_SOFTWARE,
					extack);
	if (ret)
		goto unlock;

	if (enable)
		ret = ice_dpll_pin_enable(hw, target, d->dpll_idx, type, extack);
	else
		ret = ice_dpll_pin_disable(hw, target, type, extack);
	if (!ret)
		ret = ice_dpll_pin_state_update(pf, target, type, extack);

unlock:
	mutex_unlock(&pf->dplls.lock);

	return ret;
}

/**
 * ice_dpll_sw_pin_state_get - get SW pin state
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @state: on success holds state of the pin
 * @extack: error reporting
 *
 * Dpll subsystem callback. Check state of a SW pin.
 *
 * Context: Acquires and releases pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error
 */
static int
ice_dpll_sw_pin_state_get(const struct dpll_pin *pin, void *pin_priv,
			  const struct dpll_device *dpll, void *dpll_priv,
			  enum dpll_pin_state *state,
			  struct netlink_ext_ack *extack)
{
	struct ice_dpll_pin *p = pin_priv;
	struct ice_dpll *d = dpll_priv;
	struct ice_pf *pf = p->pf;
	int ret = 0;

	if (ice_dpll_is_reset(pf, extack))
		return -EBUSY;
	mutex_lock(&pf->dplls.lock);
	if (!p->active) {
		*state = DPLL_PIN_STATE_DISCONNECTED;
		goto unlock;
	}

	if (p->direction == DPLL_PIN_DIRECTION_INPUT) {
		ret = ice_dpll_pin_state_update(pf, p->input,
						ICE_DPLL_PIN_TYPE_INPUT,
						extack);
		if (ret)
			goto unlock;
		*state = p->input->state[d->dpll_idx];
	} else {
		ret = ice_dpll_pin_state_update(pf, p->output,
						ICE_DPLL_PIN_TYPE_OUTPUT,
						extack);
		if (ret)
			goto unlock;
		*state = p->output->state[d->dpll_idx];
	}
unlock:
	mutex_unlock(&pf->dplls.lock);

	return ret;
}

/**
 * ice_dpll_sma_pin_state_set - set SMA pin state on dpll device
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @state: requested state of the pin
 * @extack: error reporting
 *
 * Dpll subsystem callback. Set state of a pin.
 *
 * Context: Acquires and releases pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - failed to get state
 */
static int
ice_dpll_sma_pin_state_set(const struct dpll_pin *pin, void *pin_priv,
			   const struct dpll_device *dpll, void *dpll_priv,
			   enum dpll_pin_state state,
			   struct netlink_ext_ack *extack)
{
	struct ice_dpll_pin *sma = pin_priv, *target;
	struct ice_dpll *d = dpll_priv;
	struct ice_pf *pf = sma->pf;
	enum ice_dpll_pin_type type;
	bool enable;
	int ret;

	if (ice_dpll_is_reset(pf, extack))
		return -EBUSY;

	mutex_lock(&pf->dplls.lock);
	if (!sma->active) {
		ret = ice_dpll_sma_direction_set(sma, sma->direction, extack);
		if (ret)
			goto unlock;
	}
	if (sma->direction == DPLL_PIN_DIRECTION_INPUT) {
		enable = state == DPLL_PIN_STATE_SELECTABLE;
		target = sma->input;
		type = ICE_DPLL_PIN_TYPE_INPUT;
	} else {
		enable = state == DPLL_PIN_STATE_CONNECTED;
		target = sma->output;
		type = ICE_DPLL_PIN_TYPE_OUTPUT;
	}

	if (enable)
		ret = ice_dpll_pin_enable(&pf->hw, target, d->dpll_idx, type,
					  extack);
	else
		ret = ice_dpll_pin_disable(&pf->hw, target, type, extack);
	if (!ret)
		ret = ice_dpll_pin_state_update(pf, target, type, extack);

unlock:
	mutex_unlock(&pf->dplls.lock);

	return ret;
}

/**
 * ice_dpll_input_prio_get - get dpll's input prio
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @prio: on success - returns input priority on dpll
 * @extack: error reporting
 *
 * Dpll subsystem callback. Handler for getting priority of a input pin.
 *
 * Context: Acquires pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - failure
 */
static int
ice_dpll_input_prio_get(const struct dpll_pin *pin, void *pin_priv,
			const struct dpll_device *dpll, void *dpll_priv,
			u32 *prio, struct netlink_ext_ack *extack)
{
	struct ice_dpll_pin *p = pin_priv;
	struct ice_dpll *d = dpll_priv;
	struct ice_pf *pf = d->pf;

	mutex_lock(&pf->dplls.lock);
	*prio = d->input_prio[p->idx];
	mutex_unlock(&pf->dplls.lock);

	return 0;
}

/**
 * ice_dpll_input_prio_set - set dpll input prio
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @prio: input priority to be set on dpll
 * @extack: error reporting
 *
 * Dpll subsystem callback. Handler for setting priority of a input pin.
 *
 * Context: Acquires pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - failure
 */
static int
ice_dpll_input_prio_set(const struct dpll_pin *pin, void *pin_priv,
			const struct dpll_device *dpll, void *dpll_priv,
			u32 prio, struct netlink_ext_ack *extack)
{
	struct ice_dpll_pin *p = pin_priv;
	struct ice_dpll *d = dpll_priv;
	struct ice_pf *pf = d->pf;
	int ret;

	if (ice_dpll_is_reset(pf, extack))
		return -EBUSY;

	mutex_lock(&pf->dplls.lock);
	ret = ice_dpll_hw_input_prio_set(pf, d, p, prio, extack);
	mutex_unlock(&pf->dplls.lock);

	return ret;
}

static int
ice_dpll_sw_input_prio_get(const struct dpll_pin *pin, void *pin_priv,
			   const struct dpll_device *dpll, void *dpll_priv,
			   u32 *prio, struct netlink_ext_ack *extack)
{
	struct ice_dpll_pin *p = pin_priv;
	struct ice_dpll *d = dpll_priv;
	struct ice_pf *pf = d->pf;

	mutex_lock(&pf->dplls.lock);
	if (p->input && p->direction == DPLL_PIN_DIRECTION_INPUT)
		*prio = d->input_prio[p->input->idx];
	else
		*prio = ICE_DPLL_PIN_PRIO_OUTPUT;
	mutex_unlock(&pf->dplls.lock);

	return 0;
}

static int
ice_dpll_sw_input_prio_set(const struct dpll_pin *pin, void *pin_priv,
			   const struct dpll_device *dpll, void *dpll_priv,
			   u32 prio, struct netlink_ext_ack *extack)
{
	struct ice_dpll_pin *p = pin_priv;
	struct ice_dpll *d = dpll_priv;
	struct ice_pf *pf = d->pf;
	int ret;

	if (!p->input || p->direction != DPLL_PIN_DIRECTION_INPUT)
		return -EINVAL;
	if (ice_dpll_is_reset(pf, extack))
		return -EBUSY;

	mutex_lock(&pf->dplls.lock);
	ret = ice_dpll_hw_input_prio_set(pf, d, p->input, prio, extack);
	mutex_unlock(&pf->dplls.lock);

	return ret;
}

/**
 * ice_dpll_input_direction - callback for get input pin direction
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @direction: holds input pin direction
 * @extack: error reporting
 *
 * Dpll subsystem callback. Handler for getting direction of a input pin.
 *
 * Return:
 * * 0 - success
 */
static int
ice_dpll_input_direction(const struct dpll_pin *pin, void *pin_priv,
			 const struct dpll_device *dpll, void *dpll_priv,
			 enum dpll_pin_direction *direction,
			 struct netlink_ext_ack *extack)
{
	*direction = DPLL_PIN_DIRECTION_INPUT;

	return 0;
}

/**
 * ice_dpll_output_direction - callback for get output pin direction
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @direction: holds output pin direction
 * @extack: error reporting
 *
 * Dpll subsystem callback. Handler for getting direction of an output pin.
 *
 * Return:
 * * 0 - success
 */
static int
ice_dpll_output_direction(const struct dpll_pin *pin, void *pin_priv,
			  const struct dpll_device *dpll, void *dpll_priv,
			  enum dpll_pin_direction *direction,
			  struct netlink_ext_ack *extack)
{
	*direction = DPLL_PIN_DIRECTION_OUTPUT;

	return 0;
}

/**
 * ice_dpll_pin_sma_direction_set - callback for set SMA pin direction
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @direction: requested pin direction
 * @extack: error reporting
 *
 * Dpll subsystem callback. Handler for setting direction of a SMA pin.
 *
 * Context: Acquires and releases pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error
 */
static int
ice_dpll_pin_sma_direction_set(const struct dpll_pin *pin, void *pin_priv,
			       const struct dpll_device *dpll, void *dpll_priv,
			       enum dpll_pin_direction direction,
			       struct netlink_ext_ack *extack)
{
	struct ice_dpll_pin *p = pin_priv;
	struct ice_pf *pf = p->pf;
	int ret;

	if (ice_dpll_is_reset(pf, extack))
		return -EBUSY;

	mutex_lock(&pf->dplls.lock);
	ret = ice_dpll_sma_direction_set(p, direction, extack);
	mutex_unlock(&pf->dplls.lock);

	return ret;
}

/**
 * ice_dpll_pin_sw_direction_get - callback for get SW pin direction
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @direction: on success holds pin direction
 * @extack: error reporting
 *
 * Dpll subsystem callback. Handler for getting direction of a SMA pin.
 *
 * Context: Acquires and releases pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error
 */
static int
ice_dpll_pin_sw_direction_get(const struct dpll_pin *pin, void *pin_priv,
			      const struct dpll_device *dpll, void *dpll_priv,
			      enum dpll_pin_direction *direction,
			      struct netlink_ext_ack *extack)
{
	struct ice_dpll_pin *p = pin_priv;
	struct ice_pf *pf = p->pf;

	if (ice_dpll_is_reset(pf, extack))
		return -EBUSY;
	mutex_lock(&pf->dplls.lock);
	*direction = p->direction;
	mutex_unlock(&pf->dplls.lock);

	return 0;
}

/**
 * ice_dpll_pin_phase_adjust_get - callback for get pin phase adjust value
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @phase_adjust: on success holds pin phase_adjust value
 * @extack: error reporting
 *
 * Dpll subsystem callback. Handler for getting phase adjust value of a pin.
 *
 * Context: Acquires pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error
 */
static int
ice_dpll_pin_phase_adjust_get(const struct dpll_pin *pin, void *pin_priv,
			      const struct dpll_device *dpll, void *dpll_priv,
			      s32 *phase_adjust,
			      struct netlink_ext_ack *extack)
{
	struct ice_dpll_pin *p = pin_priv;
	struct ice_pf *pf = p->pf;

	mutex_lock(&pf->dplls.lock);
	*phase_adjust = p->phase_adjust;
	mutex_unlock(&pf->dplls.lock);

	return 0;
}

/**
 * ice_dpll_pin_phase_adjust_set - helper for setting a pin phase adjust value
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @phase_adjust: phase_adjust to be set
 * @extack: error reporting
 * @type: type of a pin
 *
 * Helper for dpll subsystem callback. Handler for setting phase adjust value
 * of a pin.
 *
 * Context: Acquires pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error
 */
static int
ice_dpll_pin_phase_adjust_set(const struct dpll_pin *pin, void *pin_priv,
			      const struct dpll_device *dpll, void *dpll_priv,
			      s32 phase_adjust,
			      struct netlink_ext_ack *extack,
			      enum ice_dpll_pin_type type)
{
	struct ice_dpll_pin *p = pin_priv;
	struct ice_dpll *d = dpll_priv;
	struct ice_pf *pf = d->pf;
	u8 flag, flags_en = 0;
	int ret;

	if (ice_dpll_is_reset(pf, extack))
		return -EBUSY;

	mutex_lock(&pf->dplls.lock);
	switch (type) {
	case ICE_DPLL_PIN_TYPE_INPUT:
		flag = ICE_AQC_SET_CGU_IN_CFG_FLG1_UPDATE_DELAY;
		if (p->flags[0] & ICE_AQC_GET_CGU_IN_CFG_FLG2_ESYNC_EN)
			flags_en |= ICE_AQC_SET_CGU_IN_CFG_FLG2_ESYNC_EN;
		if (p->flags[0] & ICE_AQC_GET_CGU_IN_CFG_FLG2_INPUT_EN)
			flags_en |= ICE_AQC_SET_CGU_IN_CFG_FLG2_INPUT_EN;
		ret = ice_aq_set_input_pin_cfg(&pf->hw, p->idx, flag, flags_en,
					       0, phase_adjust);
		break;
	case ICE_DPLL_PIN_TYPE_OUTPUT:
		flag = ICE_AQC_SET_CGU_OUT_CFG_UPDATE_PHASE;
		if (p->flags[0] & ICE_AQC_GET_CGU_OUT_CFG_OUT_EN)
			flag |= ICE_AQC_SET_CGU_OUT_CFG_OUT_EN;
		if (p->flags[0] & ICE_AQC_GET_CGU_OUT_CFG_ESYNC_EN)
			flag |= ICE_AQC_SET_CGU_OUT_CFG_ESYNC_EN;
		ret = ice_aq_set_output_pin_cfg(&pf->hw, p->idx, flag, 0, 0,
						phase_adjust);
		break;
	default:
		ret = -EINVAL;
	}
	if (!ret)
		p->phase_adjust = phase_adjust;
	mutex_unlock(&pf->dplls.lock);
	if (ret)
		NL_SET_ERR_MSG_FMT(extack,
				   "err:%d %s failed to set pin phase_adjust:%d for pin:%u on dpll:%u",
				   ret,
				   libie_aq_str(pf->hw.adminq.sq_last_status),
				   phase_adjust, p->idx, d->dpll_idx);

	return ret;
}

/**
 * ice_dpll_input_phase_adjust_set - callback for set input pin phase adjust
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @phase_adjust: phase_adjust to be set
 * @extack: error reporting
 *
 * Dpll subsystem callback. Wraps a handler for setting phase adjust on input
 * pin.
 *
 * Context: Calls a function which acquires and releases pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error
 */
static int
ice_dpll_input_phase_adjust_set(const struct dpll_pin *pin, void *pin_priv,
				const struct dpll_device *dpll, void *dpll_priv,
				s32 phase_adjust,
				struct netlink_ext_ack *extack)
{
	return ice_dpll_pin_phase_adjust_set(pin, pin_priv, dpll, dpll_priv,
					     phase_adjust, extack,
					     ICE_DPLL_PIN_TYPE_INPUT);
}

/**
 * ice_dpll_output_phase_adjust_set - callback for set output pin phase adjust
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @phase_adjust: phase_adjust to be set
 * @extack: error reporting
 *
 * Dpll subsystem callback. Wraps a handler for setting phase adjust on output
 * pin.
 *
 * Context: Calls a function which acquires pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error
 */
static int
ice_dpll_output_phase_adjust_set(const struct dpll_pin *pin, void *pin_priv,
				 const struct dpll_device *dpll, void *dpll_priv,
				 s32 phase_adjust,
				 struct netlink_ext_ack *extack)
{
	return ice_dpll_pin_phase_adjust_set(pin, pin_priv, dpll, dpll_priv,
					     phase_adjust, extack,
					     ICE_DPLL_PIN_TYPE_OUTPUT);
}

/**
 * ice_dpll_sw_phase_adjust_get - callback for get SW pin phase adjust
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @phase_adjust: on success holds phase adjust value
 * @extack: error reporting
 *
 * Dpll subsystem callback. Wraps a handler for getting phase adjust on sw
 * pin.
 *
 * Context: Calls a function which acquires and releases pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error
 */
static int
ice_dpll_sw_phase_adjust_get(const struct dpll_pin *pin, void *pin_priv,
			     const struct dpll_device *dpll, void *dpll_priv,
			     s32 *phase_adjust,
			     struct netlink_ext_ack *extack)
{
	struct ice_dpll_pin *p = pin_priv;

	if (p->direction == DPLL_PIN_DIRECTION_INPUT)
		return ice_dpll_pin_phase_adjust_get(p->input->pin, p->input,
						     dpll, dpll_priv,
						     phase_adjust, extack);
	else
		return ice_dpll_pin_phase_adjust_get(p->output->pin, p->output,
						     dpll, dpll_priv,
						     phase_adjust, extack);
}

/**
 * ice_dpll_sw_phase_adjust_set - callback for set SW pin phase adjust value
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @phase_adjust: phase_adjust to be set
 * @extack: error reporting
 *
 * Dpll subsystem callback. Wraps a handler for setting phase adjust on output
 * pin.
 *
 * Context: Calls a function which acquires and releases pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error
 */
static int
ice_dpll_sw_phase_adjust_set(const struct dpll_pin *pin, void *pin_priv,
			     const struct dpll_device *dpll, void *dpll_priv,
			     s32 phase_adjust,
			     struct netlink_ext_ack *extack)
{
	struct ice_dpll_pin *p = pin_priv;

	if (!p->active) {
		NL_SET_ERR_MSG(extack, "pin is not active");
		return -EINVAL;
	}
	if (p->direction == DPLL_PIN_DIRECTION_INPUT)
		return ice_dpll_pin_phase_adjust_set(p->input->pin, p->input,
						     dpll, dpll_priv,
						     phase_adjust, extack,
						     ICE_DPLL_PIN_TYPE_INPUT);
	else
		return ice_dpll_pin_phase_adjust_set(p->output->pin, p->output,
						     dpll, dpll_priv,
						     phase_adjust, extack,
						     ICE_DPLL_PIN_TYPE_OUTPUT);
}

#define ICE_DPLL_PHASE_OFFSET_DIVIDER	100
#define ICE_DPLL_PHASE_OFFSET_FACTOR		\
	(DPLL_PHASE_OFFSET_DIVIDER / ICE_DPLL_PHASE_OFFSET_DIVIDER)
/**
 * ice_dpll_phase_offset_get - callback for get dpll phase shift value
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @phase_offset: on success holds pin phase_offset value
 * @extack: error reporting
 *
 * Dpll subsystem callback. Handler for getting phase shift value between
 * dpll's input and output.
 *
 * Context: Acquires pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error
 */
static int
ice_dpll_phase_offset_get(const struct dpll_pin *pin, void *pin_priv,
			  const struct dpll_device *dpll, void *dpll_priv,
			  s64 *phase_offset, struct netlink_ext_ack *extack)
{
	struct ice_dpll_pin *p = pin_priv;
	struct ice_dpll *d = dpll_priv;
	struct ice_pf *pf = d->pf;

	mutex_lock(&pf->dplls.lock);
	if (d->active_input == pin || (p->input &&
				       d->active_input == p->input->pin))
		*phase_offset = d->phase_offset * ICE_DPLL_PHASE_OFFSET_FACTOR;
	else if (d->phase_offset_monitor_period)
		*phase_offset = p->phase_offset * ICE_DPLL_PHASE_OFFSET_FACTOR;
	else
		*phase_offset = 0;
	mutex_unlock(&pf->dplls.lock);

	return 0;
}

/**
 * ice_dpll_output_esync_set - callback for setting embedded sync
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @freq: requested embedded sync frequency
 * @extack: error reporting
 *
 * Dpll subsystem callback. Handler for setting embedded sync frequency value
 * on output pin.
 *
 * Context: Acquires pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error
 */
static int
ice_dpll_output_esync_set(const struct dpll_pin *pin, void *pin_priv,
			  const struct dpll_device *dpll, void *dpll_priv,
			  u64 freq, struct netlink_ext_ack *extack)
{
	struct ice_dpll_pin *p = pin_priv;
	struct ice_dpll *d = dpll_priv;
	struct ice_pf *pf = d->pf;
	u8 flags = 0;
	int ret;

	if (ice_dpll_is_reset(pf, extack))
		return -EBUSY;
	mutex_lock(&pf->dplls.lock);
	if (p->flags[0] & ICE_AQC_GET_CGU_OUT_CFG_OUT_EN)
		flags = ICE_AQC_SET_CGU_OUT_CFG_OUT_EN;
	if (freq == DPLL_PIN_FREQUENCY_1_HZ) {
		if (p->flags[0] & ICE_AQC_GET_CGU_OUT_CFG_ESYNC_EN) {
			ret = 0;
		} else {
			flags |= ICE_AQC_SET_CGU_OUT_CFG_ESYNC_EN;
			ret = ice_aq_set_output_pin_cfg(&pf->hw, p->idx, flags,
							0, 0, 0);
		}
	} else {
		if (!(p->flags[0] & ICE_AQC_GET_CGU_OUT_CFG_ESYNC_EN)) {
			ret = 0;
		} else {
			flags &= ~ICE_AQC_SET_CGU_OUT_CFG_ESYNC_EN;
			ret = ice_aq_set_output_pin_cfg(&pf->hw, p->idx, flags,
							0, 0, 0);
		}
	}
	mutex_unlock(&pf->dplls.lock);

	return ret;
}

/**
 * ice_dpll_output_esync_get - callback for getting embedded sync config
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @esync: on success holds embedded sync pin properties
 * @extack: error reporting
 *
 * Dpll subsystem callback. Handler for getting embedded sync frequency value
 * and capabilities on output pin.
 *
 * Context: Acquires pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error
 */
static int
ice_dpll_output_esync_get(const struct dpll_pin *pin, void *pin_priv,
			  const struct dpll_device *dpll, void *dpll_priv,
			  struct dpll_pin_esync *esync,
			  struct netlink_ext_ack *extack)
{
	struct ice_dpll_pin *p = pin_priv;
	struct ice_dpll *d = dpll_priv;
	struct ice_pf *pf = d->pf;

	if (ice_dpll_is_reset(pf, extack))
		return -EBUSY;
	mutex_lock(&pf->dplls.lock);
	if (!(p->flags[0] & ICE_AQC_GET_CGU_OUT_CFG_ESYNC_ABILITY) ||
	    p->freq != DPLL_PIN_FREQUENCY_10_MHZ) {
		mutex_unlock(&pf->dplls.lock);
		return -EOPNOTSUPP;
	}
	esync->range = ice_esync_range;
	esync->range_num = ARRAY_SIZE(ice_esync_range);
	if (p->flags[0] & ICE_AQC_GET_CGU_OUT_CFG_ESYNC_EN) {
		esync->freq = DPLL_PIN_FREQUENCY_1_HZ;
		esync->pulse = ICE_DPLL_PIN_ESYNC_PULSE_HIGH_PERCENT;
	} else {
		esync->freq = 0;
		esync->pulse = 0;
	}
	mutex_unlock(&pf->dplls.lock);

	return 0;
}

/**
 * ice_dpll_input_esync_set - callback for setting embedded sync
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @freq: requested embedded sync frequency
 * @extack: error reporting
 *
 * Dpll subsystem callback. Handler for setting embedded sync frequency value
 * on input pin.
 *
 * Context: Acquires pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error
 */
static int
ice_dpll_input_esync_set(const struct dpll_pin *pin, void *pin_priv,
			 const struct dpll_device *dpll, void *dpll_priv,
			 u64 freq, struct netlink_ext_ack *extack)
{
	struct ice_dpll_pin *p = pin_priv;
	struct ice_dpll *d = dpll_priv;
	struct ice_pf *pf = d->pf;
	u8 flags_en = 0;
	int ret;

	if (ice_dpll_is_reset(pf, extack))
		return -EBUSY;
	mutex_lock(&pf->dplls.lock);
	if (p->flags[0] & ICE_AQC_GET_CGU_IN_CFG_FLG2_INPUT_EN)
		flags_en = ICE_AQC_SET_CGU_IN_CFG_FLG2_INPUT_EN;
	if (freq == DPLL_PIN_FREQUENCY_1_HZ) {
		if (p->flags[0] & ICE_AQC_GET_CGU_IN_CFG_FLG2_ESYNC_EN) {
			ret = 0;
		} else {
			flags_en |= ICE_AQC_SET_CGU_IN_CFG_FLG2_ESYNC_EN;
			ret = ice_aq_set_input_pin_cfg(&pf->hw, p->idx, 0,
						       flags_en, 0, 0);
		}
	} else {
		if (!(p->flags[0] & ICE_AQC_GET_CGU_IN_CFG_FLG2_ESYNC_EN)) {
			ret = 0;
		} else {
			flags_en &= ~ICE_AQC_SET_CGU_IN_CFG_FLG2_ESYNC_EN;
			ret = ice_aq_set_input_pin_cfg(&pf->hw, p->idx, 0,
						       flags_en, 0, 0);
		}
	}
	mutex_unlock(&pf->dplls.lock);

	return ret;
}

/**
 * ice_dpll_input_esync_get - callback for getting embedded sync config
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @esync: on success holds embedded sync pin properties
 * @extack: error reporting
 *
 * Dpll subsystem callback. Handler for getting embedded sync frequency value
 * and capabilities on input pin.
 *
 * Context: Acquires pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error
 */
static int
ice_dpll_input_esync_get(const struct dpll_pin *pin, void *pin_priv,
			 const struct dpll_device *dpll, void *dpll_priv,
			 struct dpll_pin_esync *esync,
			 struct netlink_ext_ack *extack)
{
	struct ice_dpll_pin *p = pin_priv;
	struct ice_dpll *d = dpll_priv;
	struct ice_pf *pf = d->pf;

	if (ice_dpll_is_reset(pf, extack))
		return -EBUSY;
	mutex_lock(&pf->dplls.lock);
	if (!(p->status & ICE_AQC_GET_CGU_IN_CFG_STATUS_ESYNC_CAP) ||
	    p->freq != DPLL_PIN_FREQUENCY_10_MHZ) {
		mutex_unlock(&pf->dplls.lock);
		return -EOPNOTSUPP;
	}
	esync->range = ice_esync_range;
	esync->range_num = ARRAY_SIZE(ice_esync_range);
	if (p->flags[0] & ICE_AQC_GET_CGU_IN_CFG_FLG2_ESYNC_EN) {
		esync->freq = DPLL_PIN_FREQUENCY_1_HZ;
		esync->pulse = ICE_DPLL_PIN_ESYNC_PULSE_HIGH_PERCENT;
	} else {
		esync->freq = 0;
		esync->pulse = 0;
	}
	mutex_unlock(&pf->dplls.lock);

	return 0;
}

/**
 * ice_dpll_sw_esync_set - callback for setting embedded sync on SW pin
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @freq: requested embedded sync frequency
 * @extack: error reporting
 *
 * Dpll subsystem callback. Handler for setting embedded sync frequency value
 * on SW pin.
 *
 * Context: Calls a function which acquires and releases pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error
 */
static int
ice_dpll_sw_esync_set(const struct dpll_pin *pin, void *pin_priv,
		      const struct dpll_device *dpll, void *dpll_priv,
		      u64 freq, struct netlink_ext_ack *extack)
{
	struct ice_dpll_pin *p = pin_priv;

	if (!p->active) {
		NL_SET_ERR_MSG(extack, "pin is not active");
		return -EINVAL;
	}
	if (p->direction == DPLL_PIN_DIRECTION_INPUT)
		return ice_dpll_input_esync_set(p->input->pin, p->input, dpll,
						dpll_priv, freq, extack);
	else
		return ice_dpll_output_esync_set(p->output->pin, p->output,
						 dpll, dpll_priv, freq, extack);
}

/**
 * ice_dpll_sw_esync_get - callback for getting embedded sync on SW pin
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @dpll: registered dpll pointer
 * @dpll_priv: private data pointer passed on dpll registration
 * @esync: on success holds embedded sync frequency and properties
 * @extack: error reporting
 *
 * Dpll subsystem callback. Handler for getting embedded sync frequency value
 * of SW pin.
 *
 * Context: Calls a function which acquires and releases pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error
 */
static int
ice_dpll_sw_esync_get(const struct dpll_pin *pin, void *pin_priv,
		      const struct dpll_device *dpll, void *dpll_priv,
		      struct dpll_pin_esync *esync,
		      struct netlink_ext_ack *extack)
{
	struct ice_dpll_pin *p = pin_priv;

	if (p->direction == DPLL_PIN_DIRECTION_INPUT)
		return ice_dpll_input_esync_get(p->input->pin, p->input, dpll,
						dpll_priv, esync, extack);
	else
		return ice_dpll_output_esync_get(p->output->pin, p->output,
						 dpll, dpll_priv, esync,
						 extack);
}

/*
 * ice_dpll_input_ref_sync_set - callback for setting reference sync feature
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @ref_pin: pin pointer for reference sync pair
 * @ref_pin_priv: private data pointer of ref_pin
 * @state: requested state for reference sync for pin pair
 * @extack: error reporting
 *
 * Dpll subsystem callback. Handler for setting reference sync frequency
 * feature for input pin.
 *
 * Context: Acquires and releases pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error
 */
static int
ice_dpll_input_ref_sync_set(const struct dpll_pin *pin, void *pin_priv,
			    const struct dpll_pin *ref_pin, void *ref_pin_priv,
			    const enum dpll_pin_state state,
			    struct netlink_ext_ack *extack)
{
	struct ice_dpll_pin *p = pin_priv;
	struct ice_pf *pf = p->pf;
	u8 flags_en = 0;
	int ret;

	if (ice_dpll_is_reset(pf, extack))
		return -EBUSY;
	mutex_lock(&pf->dplls.lock);

	if (p->flags[0] & ICE_AQC_GET_CGU_IN_CFG_FLG2_INPUT_EN)
		flags_en = ICE_AQC_SET_CGU_IN_CFG_FLG2_INPUT_EN;
	if (state == DPLL_PIN_STATE_CONNECTED)
		flags_en |= ICE_AQC_CGU_IN_CFG_FLG2_REFSYNC_EN;
	ret = ice_aq_set_input_pin_cfg(&pf->hw, p->idx, 0, flags_en, 0, 0);
	if (!ret)
		ret = ice_dpll_pin_state_update(pf, p, ICE_DPLL_PIN_TYPE_INPUT,
						extack);
	mutex_unlock(&pf->dplls.lock);

	return ret;
}

/**
 * ice_dpll_input_ref_sync_get - callback for getting reference sync config
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @ref_pin: pin pointer for reference sync pair
 * @ref_pin_priv: private data pointer of ref_pin
 * @state: on success holds reference sync state for pin pair
 * @extack: error reporting
 *
 * Dpll subsystem callback. Handler for setting reference sync frequency
 * feature for input pin.
 *
 * Context: Acquires and releases pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error
 */
static int
ice_dpll_input_ref_sync_get(const struct dpll_pin *pin, void *pin_priv,
			    const struct dpll_pin *ref_pin, void *ref_pin_priv,
			    enum dpll_pin_state *state,
			    struct netlink_ext_ack *extack)
{
	struct ice_dpll_pin *p = pin_priv;
	struct ice_pf *pf = p->pf;

	if (ice_dpll_is_reset(pf, extack))
		return -EBUSY;
	mutex_lock(&pf->dplls.lock);
	if (p->flags[0] & ICE_AQC_CGU_IN_CFG_FLG2_REFSYNC_EN)
		*state = DPLL_PIN_STATE_CONNECTED;
	else
		*state = DPLL_PIN_STATE_DISCONNECTED;
	mutex_unlock(&pf->dplls.lock);

	return 0;
}

/*
 * ice_dpll_sw_input_ref_sync_set - callback for setting reference sync feature
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @ref_pin: pin pointer for reference sync pair
 * @ref_pin_priv: private data pointer of ref_pin
 * @state: requested state for reference sync for pin pair
 * @extack: error reporting
 *
 * Dpll subsystem callback. Handler for setting reference sync
 * feature for input pins.
 *
 * Context: Calls a function which acquires and releases pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error
 */
static int
ice_dpll_sw_input_ref_sync_set(const struct dpll_pin *pin, void *pin_priv,
			       const struct dpll_pin *ref_pin,
			       void *ref_pin_priv,
			       const enum dpll_pin_state state,
			       struct netlink_ext_ack *extack)
{
	struct ice_dpll_pin *p = pin_priv;

	return ice_dpll_input_ref_sync_set(pin, p->input, ref_pin, ref_pin_priv,
					   state, extack);
}

/**
 * ice_dpll_sw_input_ref_sync_get - callback for getting reference sync config
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @ref_pin: pin pointer for reference sync pair
 * @ref_pin_priv: private data pointer of ref_pin
 * @state: on success holds reference sync state for pin pair
 * @extack: error reporting
 *
 * Dpll subsystem callback. Handler for setting reference sync feature for
 * input pins.
 *
 * Context: Calls a function which acquires and releases pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - error
 */
static int
ice_dpll_sw_input_ref_sync_get(const struct dpll_pin *pin, void *pin_priv,
			       const struct dpll_pin *ref_pin,
			       void *ref_pin_priv,
			       enum dpll_pin_state *state,
			       struct netlink_ext_ack *extack)
{
	struct ice_dpll_pin *p = pin_priv;

	return ice_dpll_input_ref_sync_get(pin, p->input, ref_pin, ref_pin_priv,
					   state, extack);
}

/**
 * ice_dpll_rclk_state_on_pin_set - set a state on rclk pin
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @parent_pin: pin parent pointer
 * @parent_pin_priv: parent private data pointer passed on pin registration
 * @state: state to be set on pin
 * @extack: error reporting
 *
 * Dpll subsystem callback, set a state of a rclk pin on a parent pin
 *
 * Context: Acquires pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - failure
 */
static int
ice_dpll_rclk_state_on_pin_set(const struct dpll_pin *pin, void *pin_priv,
			       const struct dpll_pin *parent_pin,
			       void *parent_pin_priv,
			       enum dpll_pin_state state,
			       struct netlink_ext_ack *extack)
{
	struct ice_dpll_pin *p = pin_priv, *parent = parent_pin_priv;
	bool enable = state == DPLL_PIN_STATE_CONNECTED;
	struct ice_pf *pf = p->pf;
	int ret = -EINVAL;
	u32 hw_idx;

	if (ice_dpll_is_reset(pf, extack))
		return -EBUSY;

	mutex_lock(&pf->dplls.lock);
	hw_idx = parent->idx - pf->dplls.base_rclk_idx;
	if (hw_idx >= pf->dplls.num_inputs)
		goto unlock;

	if ((enable && p->state[hw_idx] == DPLL_PIN_STATE_CONNECTED) ||
	    (!enable && p->state[hw_idx] == DPLL_PIN_STATE_DISCONNECTED)) {
		NL_SET_ERR_MSG_FMT(extack,
				   "pin:%u state:%u on parent:%u already set",
				   p->idx, state, parent->idx);
		goto unlock;
	}
	ret = ice_aq_set_phy_rec_clk_out(&pf->hw, hw_idx, enable,
					 &p->freq);
	if (ret)
		NL_SET_ERR_MSG_FMT(extack,
				   "err:%d %s failed to set pin state:%u for pin:%u on parent:%u",
				   ret,
				   libie_aq_str(pf->hw.adminq.sq_last_status),
				   state, p->idx, parent->idx);
unlock:
	mutex_unlock(&pf->dplls.lock);

	return ret;
}

/**
 * ice_dpll_rclk_state_on_pin_get - get a state of rclk pin
 * @pin: pointer to a pin
 * @pin_priv: private data pointer passed on pin registration
 * @parent_pin: pin parent pointer
 * @parent_pin_priv: pin parent priv data pointer passed on pin registration
 * @state: on success holds pin state on parent pin
 * @extack: error reporting
 *
 * dpll subsystem callback, get a state of a recovered clock pin.
 *
 * Context: Acquires pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - failure
 */
static int
ice_dpll_rclk_state_on_pin_get(const struct dpll_pin *pin, void *pin_priv,
			       const struct dpll_pin *parent_pin,
			       void *parent_pin_priv,
			       enum dpll_pin_state *state,
			       struct netlink_ext_ack *extack)
{
	struct ice_dpll_pin *p = pin_priv, *parent = parent_pin_priv;
	struct ice_pf *pf = p->pf;
	int ret = -EINVAL;
	u32 hw_idx;

	if (ice_dpll_is_reset(pf, extack))
		return -EBUSY;

	mutex_lock(&pf->dplls.lock);
	hw_idx = parent->idx - pf->dplls.base_rclk_idx;
	if (hw_idx >= pf->dplls.num_inputs)
		goto unlock;

	ret = ice_dpll_pin_state_update(pf, p, ICE_DPLL_PIN_TYPE_RCLK_INPUT,
					extack);
	if (ret)
		goto unlock;

	*state = p->state[hw_idx];
	ret = 0;
unlock:
	mutex_unlock(&pf->dplls.lock);

	return ret;
}

static const struct dpll_pin_ops ice_dpll_rclk_ops = {
	.state_on_pin_set = ice_dpll_rclk_state_on_pin_set,
	.state_on_pin_get = ice_dpll_rclk_state_on_pin_get,
	.direction_get = ice_dpll_input_direction,
};

static const struct dpll_pin_ops ice_dpll_pin_sma_ops = {
	.state_on_dpll_set = ice_dpll_sma_pin_state_set,
	.state_on_dpll_get = ice_dpll_sw_pin_state_get,
	.direction_get = ice_dpll_pin_sw_direction_get,
	.direction_set = ice_dpll_pin_sma_direction_set,
	.prio_get = ice_dpll_sw_input_prio_get,
	.prio_set = ice_dpll_sw_input_prio_set,
	.frequency_get = ice_dpll_sw_pin_frequency_get,
	.frequency_set = ice_dpll_sw_pin_frequency_set,
	.phase_adjust_get = ice_dpll_sw_phase_adjust_get,
	.phase_adjust_set = ice_dpll_sw_phase_adjust_set,
	.phase_offset_get = ice_dpll_phase_offset_get,
	.esync_set = ice_dpll_sw_esync_set,
	.esync_get = ice_dpll_sw_esync_get,
	.ref_sync_set = ice_dpll_sw_input_ref_sync_set,
	.ref_sync_get = ice_dpll_sw_input_ref_sync_get,
};

static const struct dpll_pin_ops ice_dpll_pin_ufl_ops = {
	.state_on_dpll_set = ice_dpll_ufl_pin_state_set,
	.state_on_dpll_get = ice_dpll_sw_pin_state_get,
	.direction_get = ice_dpll_pin_sw_direction_get,
	.frequency_get = ice_dpll_sw_pin_frequency_get,
	.frequency_set = ice_dpll_sw_pin_frequency_set,
	.esync_set = ice_dpll_sw_esync_set,
	.esync_get = ice_dpll_sw_esync_get,
	.phase_adjust_get = ice_dpll_sw_phase_adjust_get,
	.phase_adjust_set = ice_dpll_sw_phase_adjust_set,
	.phase_offset_get = ice_dpll_phase_offset_get,
};

static const struct dpll_pin_ops ice_dpll_input_ops = {
	.frequency_get = ice_dpll_input_frequency_get,
	.frequency_set = ice_dpll_input_frequency_set,
	.state_on_dpll_get = ice_dpll_input_state_get,
	.state_on_dpll_set = ice_dpll_input_state_set,
	.prio_get = ice_dpll_input_prio_get,
	.prio_set = ice_dpll_input_prio_set,
	.direction_get = ice_dpll_input_direction,
	.phase_adjust_get = ice_dpll_pin_phase_adjust_get,
	.phase_adjust_set = ice_dpll_input_phase_adjust_set,
	.phase_offset_get = ice_dpll_phase_offset_get,
	.esync_set = ice_dpll_input_esync_set,
	.esync_get = ice_dpll_input_esync_get,
	.ref_sync_set = ice_dpll_input_ref_sync_set,
	.ref_sync_get = ice_dpll_input_ref_sync_get,
};

static const struct dpll_pin_ops ice_dpll_output_ops = {
	.frequency_get = ice_dpll_output_frequency_get,
	.frequency_set = ice_dpll_output_frequency_set,
	.state_on_dpll_get = ice_dpll_output_state_get,
	.state_on_dpll_set = ice_dpll_output_state_set,
	.direction_get = ice_dpll_output_direction,
	.phase_adjust_get = ice_dpll_pin_phase_adjust_get,
	.phase_adjust_set = ice_dpll_output_phase_adjust_set,
	.esync_set = ice_dpll_output_esync_set,
	.esync_get = ice_dpll_output_esync_get,
};

static const struct dpll_device_ops ice_dpll_ops = {
	.lock_status_get = ice_dpll_lock_status_get,
	.mode_get = ice_dpll_mode_get,
};

static const struct dpll_device_ops ice_dpll_pom_ops = {
	.lock_status_get = ice_dpll_lock_status_get,
	.mode_get = ice_dpll_mode_get,
	.phase_offset_monitor_set = ice_dpll_phase_offset_monitor_set,
	.phase_offset_monitor_get = ice_dpll_phase_offset_monitor_get,
};

/**
 * ice_generate_clock_id - generates unique clock_id for registering dpll.
 * @pf: board private structure
 *
 * Generates unique (per board) clock_id for allocation and search of dpll
 * devices in Linux dpll subsystem.
 *
 * Return: generated clock id for the board
 */
static u64 ice_generate_clock_id(struct ice_pf *pf)
{
	return pci_get_dsn(pf->pdev);
}

/**
 * ice_dpll_notify_changes - notify dpll subsystem about changes
 * @d: pointer do dpll
 *
 * Once change detected appropriate event is submitted to the dpll subsystem.
 */
static void ice_dpll_notify_changes(struct ice_dpll *d)
{
	bool pin_notified = false;

	if (d->prev_dpll_state != d->dpll_state) {
		d->prev_dpll_state = d->dpll_state;
		dpll_device_change_ntf(d->dpll);
	}
	if (d->prev_input != d->active_input) {
		if (d->prev_input)
			dpll_pin_change_ntf(d->prev_input);
		d->prev_input = d->active_input;
		if (d->active_input) {
			dpll_pin_change_ntf(d->active_input);
			pin_notified = true;
		}
	}
	if (d->prev_phase_offset != d->phase_offset) {
		d->prev_phase_offset = d->phase_offset;
		if (!pin_notified && d->active_input)
			dpll_pin_change_ntf(d->active_input);
	}
}

/**
 * ice_dpll_is_pps_phase_monitor - check if dpll capable of phase offset monitor
 * @pf: pf private structure
 *
 * Check if firmware is capable of supporting admin command to provide
 * phase offset monitoring on all the input pins on PPS dpll.
 *
 * Returns:
 * * true - PPS dpll phase offset monitoring is supported
 * * false - PPS dpll phase offset monitoring is not supported
 */
static bool ice_dpll_is_pps_phase_monitor(struct ice_pf *pf)
{
	struct ice_cgu_input_measure meas[ICE_DPLL_INPUT_REF_NUM];
	int ret = ice_aq_get_cgu_input_pin_measure(&pf->hw, DPLL_TYPE_PPS, meas,
						   ARRAY_SIZE(meas));

	if (ret && pf->hw.adminq.sq_last_status == LIBIE_AQ_RC_ESRCH)
		return false;

	return true;
}

/**
 * ice_dpll_pins_notify_mask - notify dpll subsystem about bulk pin changes
 * @pins: array of ice_dpll_pin pointers registered within dpll subsystem
 * @pin_num: number of pins
 * @phase_offset_ntf_mask: bitmask of pin indexes to notify
 *
 * Iterate over array of pins and call dpll subsystem pin notify if
 * corresponding pin index within bitmask is set.
 *
 * Context: Must be called while pf->dplls.lock is released.
 */
static void ice_dpll_pins_notify_mask(struct ice_dpll_pin *pins,
				      u8 pin_num,
				      u32 phase_offset_ntf_mask)
{
	int i = 0;

	for (i = 0; i < pin_num; i++)
		if (phase_offset_ntf_mask & (1 << i))
			dpll_pin_change_ntf(pins[i].pin);
}

/**
 * ice_dpll_pps_update_phase_offsets - update phase offset measurements
 * @pf: pf private structure
 * @phase_offset_pins_updated: returns mask of updated input pin indexes
 *
 * Read phase offset measurements for PPS dpll device and store values in
 * input pins array. On success phase_offset_pins_updated - fills bitmask of
 * updated input pin indexes, pins shall be notified.
 *
 * Context: Shall be called with pf->dplls.lock being locked.
 * Returns:
 * * 0 - success or no data available
 * * negative - AQ failure
 */
static int ice_dpll_pps_update_phase_offsets(struct ice_pf *pf,
					     u32 *phase_offset_pins_updated)
{
	struct ice_cgu_input_measure meas[ICE_DPLL_INPUT_REF_NUM];
	struct ice_dpll_pin *p;
	s64 phase_offset, tmp;
	int i, j, ret;

	*phase_offset_pins_updated = 0;
	ret = ice_aq_get_cgu_input_pin_measure(&pf->hw, DPLL_TYPE_PPS, meas,
					       ARRAY_SIZE(meas));
	if (ret && pf->hw.adminq.sq_last_status == LIBIE_AQ_RC_EAGAIN) {
		return 0;
	} else if (ret) {
		dev_err(ice_pf_to_dev(pf),
			"failed to get input pin measurements dpll=%d, ret=%d %s\n",
			DPLL_TYPE_PPS, ret,
			libie_aq_str(pf->hw.adminq.sq_last_status));
		return ret;
	}
	for (i = 0; i < pf->dplls.num_inputs; i++) {
		p = &pf->dplls.inputs[i];
		phase_offset = 0;
		for (j = 0; j < ICE_CGU_INPUT_PHASE_OFFSET_BYTES; j++) {
			tmp = meas[i].phase_offset[j];
#ifdef __LITTLE_ENDIAN
			phase_offset += tmp << 8 * j;
#else
			phase_offset += tmp << 8 *
				(ICE_CGU_INPUT_PHASE_OFFSET_BYTES - 1 - j);
#endif
		}
		phase_offset = sign_extend64(phase_offset, 47);
		if (p->phase_offset != phase_offset) {
			dev_dbg(ice_pf_to_dev(pf),
				"phase offset changed for pin:%d old:%llx, new:%llx\n",
				p->idx, p->phase_offset, phase_offset);
			p->phase_offset = phase_offset;
			*phase_offset_pins_updated |= (1 << i);
		}
	}

	return 0;
}

/**
 * ice_dpll_update_state - update dpll state
 * @pf: pf private structure
 * @d: pointer to queried dpll device
 * @init: if function called on initialization of ice dpll
 *
 * Poll current state of dpll from hw and update ice_dpll struct.
 *
 * Context: Called by kworker under pf->dplls.lock
 * Return:
 * * 0 - success
 * * negative - AQ failure
 */
static int
ice_dpll_update_state(struct ice_pf *pf, struct ice_dpll *d, bool init)
{
	struct ice_dpll_pin *p = NULL;
	int ret;

	ret = ice_get_cgu_state(&pf->hw, d->dpll_idx, d->prev_dpll_state,
				&d->input_idx, &d->ref_state, &d->eec_mode,
				&d->phase_offset, &d->dpll_state);

	dev_dbg(ice_pf_to_dev(pf),
		"update dpll=%d, prev_src_idx:%u, src_idx:%u, state:%d, prev:%d mode:%d\n",
		d->dpll_idx, d->prev_input_idx, d->input_idx,
		d->dpll_state, d->prev_dpll_state, d->mode);
	if (ret) {
		dev_err(ice_pf_to_dev(pf),
			"update dpll=%d state failed, ret=%d %s\n",
			d->dpll_idx, ret,
			libie_aq_str(pf->hw.adminq.sq_last_status));
		return ret;
	}
	if (init) {
		if (d->dpll_state == DPLL_LOCK_STATUS_LOCKED ||
		    d->dpll_state == DPLL_LOCK_STATUS_LOCKED_HO_ACQ)
			d->active_input = pf->dplls.inputs[d->input_idx].pin;
		p = &pf->dplls.inputs[d->input_idx];
		return ice_dpll_pin_state_update(pf, p,
						 ICE_DPLL_PIN_TYPE_INPUT, NULL);
	}
	if (d->dpll_state == DPLL_LOCK_STATUS_HOLDOVER ||
	    d->dpll_state == DPLL_LOCK_STATUS_UNLOCKED) {
		d->active_input = NULL;
		if (d->input_idx != ICE_DPLL_PIN_IDX_INVALID)
			p = &pf->dplls.inputs[d->input_idx];
		d->prev_input_idx = ICE_DPLL_PIN_IDX_INVALID;
		d->input_idx = ICE_DPLL_PIN_IDX_INVALID;
		if (!p)
			return 0;
		ret = ice_dpll_pin_state_update(pf, p,
						ICE_DPLL_PIN_TYPE_INPUT, NULL);
	} else if (d->input_idx != d->prev_input_idx) {
		if (d->prev_input_idx != ICE_DPLL_PIN_IDX_INVALID) {
			p = &pf->dplls.inputs[d->prev_input_idx];
			ice_dpll_pin_state_update(pf, p,
						  ICE_DPLL_PIN_TYPE_INPUT,
						  NULL);
		}
		if (d->input_idx != ICE_DPLL_PIN_IDX_INVALID) {
			p = &pf->dplls.inputs[d->input_idx];
			d->active_input = p->pin;
			ice_dpll_pin_state_update(pf, p,
						  ICE_DPLL_PIN_TYPE_INPUT,
						  NULL);
		}
		d->prev_input_idx = d->input_idx;
	}

	return ret;
}

/**
 * ice_dpll_periodic_work - DPLLs periodic worker
 * @work: pointer to kthread_work structure
 *
 * DPLLs periodic worker is responsible for polling state of dpll.
 * Context: Holds pf->dplls.lock
 */
static void ice_dpll_periodic_work(struct kthread_work *work)
{
	struct ice_dplls *d = container_of(work, struct ice_dplls, work.work);
	struct ice_pf *pf = container_of(d, struct ice_pf, dplls);
	struct ice_dpll *de = &pf->dplls.eec;
	struct ice_dpll *dp = &pf->dplls.pps;
	u32 phase_offset_ntf = 0;
	int ret = 0;

	if (ice_is_reset_in_progress(pf->state))
		goto resched;
	mutex_lock(&pf->dplls.lock);
	d->periodic_counter++;
	ret = ice_dpll_update_state(pf, de, false);
	if (!ret)
		ret = ice_dpll_update_state(pf, dp, false);
	if (!ret && dp->phase_offset_monitor_period &&
	    d->periodic_counter % dp->phase_offset_monitor_period == 0)
		ret = ice_dpll_pps_update_phase_offsets(pf, &phase_offset_ntf);
	if (ret) {
		d->cgu_state_acq_err_num++;
		/* stop rescheduling this worker */
		if (d->cgu_state_acq_err_num >
		    ICE_CGU_STATE_ACQ_ERR_THRESHOLD) {
			dev_err(ice_pf_to_dev(pf),
				"EEC/PPS DPLLs periodic work disabled\n");
			mutex_unlock(&pf->dplls.lock);
			return;
		}
	}
	mutex_unlock(&pf->dplls.lock);
	ice_dpll_notify_changes(de);
	ice_dpll_notify_changes(dp);
	if (phase_offset_ntf)
		ice_dpll_pins_notify_mask(d->inputs, d->num_inputs,
					  phase_offset_ntf);

resched:
	/* Run twice a second or reschedule if update failed */
	kthread_queue_delayed_work(d->kworker, &d->work,
				   ret ? msecs_to_jiffies(10) :
				   msecs_to_jiffies(500));
}

/**
 * ice_dpll_init_ref_sync_inputs - initialize reference sync pin pairs
 * @pf: pf private structure
 *
 * Read DPLL TLV capabilities and initialize reference sync pin pairs in
 * dpll subsystem.
 *
 * Return:
 * * 0 - success or nothing to do (no ref-sync tlv are present)
 * * negative - AQ failure
 */
static int ice_dpll_init_ref_sync_inputs(struct ice_pf *pf)
{
	struct ice_dpll_pin *inputs = pf->dplls.inputs;
	struct ice_hw *hw = &pf->hw;
	u16 addr, len, end, hdr;
	int ret;

	ret = ice_get_pfa_module_tlv(hw, &hdr, &len, ICE_SR_PFA_DPLL_DEFAULTS);
	if (ret) {
		dev_err(ice_pf_to_dev(pf),
			"Failed to read PFA dpll defaults TLV ret=%d\n", ret);
		return ret;
	}
	end = hdr + len;

	for (addr = hdr + ICE_DPLL_PFA_HEADER_LEN; addr < end;
	     addr += ICE_DPLL_PFA_ENTRY_LEN) {
		unsigned long bit, ul_mask, offset;
		u16 pin, mask, buf;
		bool valid = false;

		ret = ice_read_sr_word(hw, addr, &buf);
		if (ret)
			return ret;

		switch (buf) {
		case ICE_DPLL_PFA_REF_SYNC_TYPE:
		case ICE_DPLL_PFA_REF_SYNC_TYPE2:
		{
			u16 mask_addr = addr + ICE_DPLL_PFA_MASK_OFFSET;
			u16 val_addr = addr + ICE_DPLL_PFA_VALUE_OFFSET;

			ret = ice_read_sr_word(hw, mask_addr, &mask);
			if (ret)
				return ret;
			ret = ice_read_sr_word(hw, val_addr, &pin);
			if (ret)
				return ret;
			if (buf == ICE_DPLL_PFA_REF_SYNC_TYPE)
				pin >>= ICE_DPLL_PFA_MAILBOX_REF_SYNC_PIN_S;
			valid = true;
			break;
		}
		case ICE_DPLL_PFA_END:
			addr = end;
			break;
		default:
			continue;
		}
		if (!valid)
			continue;

		ul_mask = mask;
		offset = 0;
		for_each_set_bit(bit, &ul_mask, BITS_PER_TYPE(u16)) {
			int i, j;

			if (hw->device_id == ICE_DEV_ID_E810C_SFP &&
			    pin > ICE_DPLL_E810C_SFP_NC_START)
				offset = -ICE_DPLL_E810C_SFP_NC_PINS;
			i = pin + offset;
			j = bit + offset;
			if (i < 0 || j < 0)
				return -ERANGE;
			inputs[i].ref_sync = j;
		}
	}

	return 0;
}

/**
 * ice_dpll_release_pins - release pins resources from dpll subsystem
 * @pins: pointer to pins array
 * @count: number of pins
 *
 * Release resources of given pins array in the dpll subsystem.
 */
static void ice_dpll_release_pins(struct ice_dpll_pin *pins, int count)
{
	int i;

	for (i = 0; i < count; i++)
		dpll_pin_put(pins[i].pin);
}

/**
 * ice_dpll_get_pins - get pins from dpll subsystem
 * @pf: board private structure
 * @pins: pointer to pins array
 * @start_idx: get starts from this pin idx value
 * @count: number of pins
 * @clock_id: clock_id of dpll device
 *
 * Get pins - allocate - in dpll subsystem, store them in pin field of given
 * pins array.
 *
 * Return:
 * * 0 - success
 * * negative - allocation failure reason
 */
static int
ice_dpll_get_pins(struct ice_pf *pf, struct ice_dpll_pin *pins,
		  int start_idx, int count, u64 clock_id)
{
	int i, ret;

	for (i = 0; i < count; i++) {
		pins[i].pin = dpll_pin_get(clock_id, i + start_idx, THIS_MODULE,
					   &pins[i].prop);
		if (IS_ERR(pins[i].pin)) {
			ret = PTR_ERR(pins[i].pin);
			goto release_pins;
		}
	}

	return 0;

release_pins:
	while (--i >= 0)
		dpll_pin_put(pins[i].pin);
	return ret;
}

/**
 * ice_dpll_unregister_pins - unregister pins from a dpll
 * @dpll: dpll device pointer
 * @pins: pointer to pins array
 * @ops: callback ops registered with the pins
 * @count: number of pins
 *
 * Unregister pins of a given array of pins from given dpll device registered in
 * dpll subsystem.
 */
static void
ice_dpll_unregister_pins(struct dpll_device *dpll, struct ice_dpll_pin *pins,
			 const struct dpll_pin_ops *ops, int count)
{
	int i;

	for (i = 0; i < count; i++)
		if (!pins[i].hidden)
			dpll_pin_unregister(dpll, pins[i].pin, ops, &pins[i]);
}

/**
 * ice_dpll_pin_ref_sync_register - register reference sync pins
 * @pins: pointer to pins array
 * @count: number of pins
 *
 * Register reference sync pins in dpll subsystem.
 *
 * Return:
 * * 0 - success
 * * negative - registration failure reason
 */
static int
ice_dpll_pin_ref_sync_register(struct ice_dpll_pin *pins, int count)
{
	int ret, i;

	for (i = 0; i < count; i++) {
		if (!pins[i].hidden && pins[i].ref_sync) {
			int j = pins[i].ref_sync;

			ret = dpll_pin_ref_sync_pair_add(pins[i].pin,
							 pins[j].pin);
			if (ret)
				return ret;
		}
	}

	return 0;
}

/**
 * ice_dpll_register_pins - register pins with a dpll
 * @dpll: dpll pointer to register pins with
 * @pins: pointer to pins array
 * @ops: callback ops registered with the pins
 * @count: number of pins
 *
 * Register pins of a given array with given dpll in dpll subsystem.
 *
 * Return:
 * * 0 - success
 * * negative - registration failure reason
 */
static int
ice_dpll_register_pins(struct dpll_device *dpll, struct ice_dpll_pin *pins,
		       const struct dpll_pin_ops *ops, int count)
{
	int ret, i;

	for (i = 0; i < count; i++) {
		if (!pins[i].hidden) {
			ret = dpll_pin_register(dpll, pins[i].pin, ops, &pins[i]);
			if (ret)
				goto unregister_pins;
		}
	}

	return 0;

unregister_pins:
	while (--i >= 0)
		if (!pins[i].hidden)
			dpll_pin_unregister(dpll, pins[i].pin, ops, &pins[i]);
	return ret;
}

/**
 * ice_dpll_deinit_direct_pins - deinitialize direct pins
 * @cgu: if cgu is present and controlled by this NIC
 * @pins: pointer to pins array
 * @count: number of pins
 * @ops: callback ops registered with the pins
 * @first: dpll device pointer
 * @second: dpll device pointer
 *
 * If cgu is owned unregister pins from given dplls.
 * Release pins resources to the dpll subsystem.
 */
static void
ice_dpll_deinit_direct_pins(bool cgu, struct ice_dpll_pin *pins, int count,
			    const struct dpll_pin_ops *ops,
			    struct dpll_device *first,
			    struct dpll_device *second)
{
	if (cgu) {
		ice_dpll_unregister_pins(first, pins, ops, count);
		ice_dpll_unregister_pins(second, pins, ops, count);
	}
	ice_dpll_release_pins(pins, count);
}

/**
 * ice_dpll_init_direct_pins - initialize direct pins
 * @pf: board private structure
 * @cgu: if cgu is present and controlled by this NIC
 * @pins: pointer to pins array
 * @start_idx: on which index shall allocation start in dpll subsystem
 * @count: number of pins
 * @ops: callback ops registered with the pins
 * @first: dpll device pointer
 * @second: dpll device pointer
 *
 * Allocate directly connected pins of a given array in dpll subsystem.
 * If cgu is owned register allocated pins with given dplls.
 *
 * Return:
 * * 0 - success
 * * negative - registration failure reason
 */
static int
ice_dpll_init_direct_pins(struct ice_pf *pf, bool cgu,
			  struct ice_dpll_pin *pins, int start_idx, int count,
			  const struct dpll_pin_ops *ops,
			  struct dpll_device *first, struct dpll_device *second)
{
	int ret;

	ret = ice_dpll_get_pins(pf, pins, start_idx, count, pf->dplls.clock_id);
	if (ret)
		return ret;
	if (cgu) {
		ret = ice_dpll_register_pins(first, pins, ops, count);
		if (ret)
			goto release_pins;
		ret = ice_dpll_register_pins(second, pins, ops, count);
		if (ret)
			goto unregister_first;
	}

	return 0;

unregister_first:
	ice_dpll_unregister_pins(first, pins, ops, count);
release_pins:
	ice_dpll_release_pins(pins, count);
	return ret;
}

/**
 * ice_dpll_deinit_rclk_pin - release rclk pin resources
 * @pf: board private structure
 *
 * Deregister rclk pin from parent pins and release resources in dpll subsystem.
 */
static void ice_dpll_deinit_rclk_pin(struct ice_pf *pf)
{
	struct ice_dpll_pin *rclk = &pf->dplls.rclk;
	struct ice_vsi *vsi = ice_get_main_vsi(pf);
	struct dpll_pin *parent;
	int i;

	for (i = 0; i < rclk->num_parents; i++) {
		parent = pf->dplls.inputs[rclk->parent_idx[i]].pin;
		if (!parent)
			continue;
		dpll_pin_on_pin_unregister(parent, rclk->pin,
					   &ice_dpll_rclk_ops, rclk);
	}
	if (WARN_ON_ONCE(!vsi || !vsi->netdev))
		return;
	dpll_netdev_pin_clear(vsi->netdev);
	dpll_pin_put(rclk->pin);
}

/**
 * ice_dpll_init_rclk_pins - initialize recovered clock pin
 * @pf: board private structure
 * @pin: pin to register
 * @start_idx: on which index shall allocation start in dpll subsystem
 * @ops: callback ops registered with the pins
 *
 * Allocate resource for recovered clock pin in dpll subsystem. Register the
 * pin with the parents it has in the info. Register pin with the pf's main vsi
 * netdev.
 *
 * Return:
 * * 0 - success
 * * negative - registration failure reason
 */
static int
ice_dpll_init_rclk_pins(struct ice_pf *pf, struct ice_dpll_pin *pin,
			int start_idx, const struct dpll_pin_ops *ops)
{
	struct ice_vsi *vsi = ice_get_main_vsi(pf);
	struct dpll_pin *parent;
	int ret, i;

	if (WARN_ON((!vsi || !vsi->netdev)))
		return -EINVAL;
	ret = ice_dpll_get_pins(pf, pin, start_idx, ICE_DPLL_RCLK_NUM_PER_PF,
				pf->dplls.clock_id);
	if (ret)
		return ret;
	for (i = 0; i < pf->dplls.rclk.num_parents; i++) {
		parent = pf->dplls.inputs[pf->dplls.rclk.parent_idx[i]].pin;
		if (!parent) {
			ret = -ENODEV;
			goto unregister_pins;
		}
		ret = dpll_pin_on_pin_register(parent, pf->dplls.rclk.pin,
					       ops, &pf->dplls.rclk);
		if (ret)
			goto unregister_pins;
	}
	dpll_netdev_pin_set(vsi->netdev, pf->dplls.rclk.pin);

	return 0;

unregister_pins:
	while (i) {
		parent = pf->dplls.inputs[pf->dplls.rclk.parent_idx[--i]].pin;
		dpll_pin_on_pin_unregister(parent, pf->dplls.rclk.pin,
					   &ice_dpll_rclk_ops, &pf->dplls.rclk);
	}
	ice_dpll_release_pins(pin, ICE_DPLL_RCLK_NUM_PER_PF);
	return ret;
}

/**
 * ice_dpll_deinit_pins - deinitialize direct pins
 * @pf: board private structure
 * @cgu: if cgu is controlled by this pf
 *
 * If cgu is owned unregister directly connected pins from the dplls.
 * Release resources of directly connected pins from the dpll subsystem.
 */
static void ice_dpll_deinit_pins(struct ice_pf *pf, bool cgu)
{
	struct ice_dpll_pin *outputs = pf->dplls.outputs;
	struct ice_dpll_pin *inputs = pf->dplls.inputs;
	int num_outputs = pf->dplls.num_outputs;
	int num_inputs = pf->dplls.num_inputs;
	struct ice_dplls *d = &pf->dplls;
	struct ice_dpll *de = &d->eec;
	struct ice_dpll *dp = &d->pps;

	ice_dpll_deinit_rclk_pin(pf);
	if (cgu) {
		ice_dpll_unregister_pins(dp->dpll, inputs, &ice_dpll_input_ops,
					 num_inputs);
		ice_dpll_unregister_pins(de->dpll, inputs, &ice_dpll_input_ops,
					 num_inputs);
	}
	ice_dpll_release_pins(inputs, num_inputs);
	if (cgu) {
		ice_dpll_unregister_pins(dp->dpll, outputs,
					 &ice_dpll_output_ops, num_outputs);
		ice_dpll_unregister_pins(de->dpll, outputs,
					 &ice_dpll_output_ops, num_outputs);
		ice_dpll_release_pins(outputs, num_outputs);
		if (!pf->dplls.generic) {
			ice_dpll_deinit_direct_pins(cgu, pf->dplls.ufl,
						    ICE_DPLL_PIN_SW_NUM,
						    &ice_dpll_pin_ufl_ops,
						    pf->dplls.pps.dpll,
						    pf->dplls.eec.dpll);
			ice_dpll_deinit_direct_pins(cgu, pf->dplls.sma,
						    ICE_DPLL_PIN_SW_NUM,
						    &ice_dpll_pin_sma_ops,
						    pf->dplls.pps.dpll,
						    pf->dplls.eec.dpll);
		}
	}
}

/**
 * ice_dpll_init_pins - init pins and register pins with a dplls
 * @pf: board private structure
 * @cgu: if cgu is present and controlled by this NIC
 *
 * Initialize directly connected pf's pins within pf's dplls in a Linux dpll
 * subsystem.
 *
 * Return:
 * * 0 - success
 * * negative - initialization failure reason
 */
static int ice_dpll_init_pins(struct ice_pf *pf, bool cgu)
{
	int ret, count;

	ret = ice_dpll_init_direct_pins(pf, cgu, pf->dplls.inputs, 0,
					pf->dplls.num_inputs,
					&ice_dpll_input_ops,
					pf->dplls.eec.dpll, pf->dplls.pps.dpll);
	if (ret)
		return ret;
	count = pf->dplls.num_inputs;
	if (cgu) {
		ret = ice_dpll_init_direct_pins(pf, cgu, pf->dplls.outputs,
						count,
						pf->dplls.num_outputs,
						&ice_dpll_output_ops,
						pf->dplls.eec.dpll,
						pf->dplls.pps.dpll);
		if (ret)
			goto deinit_inputs;
		count += pf->dplls.num_outputs;
		if (!pf->dplls.generic) {
			ret = ice_dpll_init_direct_pins(pf, cgu, pf->dplls.sma,
							count,
							ICE_DPLL_PIN_SW_NUM,
							&ice_dpll_pin_sma_ops,
							pf->dplls.eec.dpll,
							pf->dplls.pps.dpll);
			if (ret)
				goto deinit_outputs;
			count += ICE_DPLL_PIN_SW_NUM;
			ret = ice_dpll_init_direct_pins(pf, cgu, pf->dplls.ufl,
							count,
							ICE_DPLL_PIN_SW_NUM,
							&ice_dpll_pin_ufl_ops,
							pf->dplls.eec.dpll,
							pf->dplls.pps.dpll);
			if (ret)
				goto deinit_sma;
			count += ICE_DPLL_PIN_SW_NUM;
		}
		ret = ice_dpll_pin_ref_sync_register(pf->dplls.inputs,
						     pf->dplls.num_inputs);
		if (ret)
			goto deinit_ufl;
		ret = ice_dpll_pin_ref_sync_register(pf->dplls.sma,
						     ICE_DPLL_PIN_SW_NUM);
		if (ret)
			goto deinit_ufl;
	} else {
		count += pf->dplls.num_outputs + 2 * ICE_DPLL_PIN_SW_NUM;
	}
	ret = ice_dpll_init_rclk_pins(pf, &pf->dplls.rclk, count + pf->hw.pf_id,
				      &ice_dpll_rclk_ops);
	if (ret)
		goto deinit_ufl;

	return 0;
deinit_ufl:
	ice_dpll_deinit_direct_pins(cgu, pf->dplls.ufl,
				    ICE_DPLL_PIN_SW_NUM,
				    &ice_dpll_pin_ufl_ops,
				    pf->dplls.pps.dpll, pf->dplls.eec.dpll);
deinit_sma:
	ice_dpll_deinit_direct_pins(cgu, pf->dplls.sma,
				    ICE_DPLL_PIN_SW_NUM,
				    &ice_dpll_pin_sma_ops,
				    pf->dplls.pps.dpll, pf->dplls.eec.dpll);
deinit_outputs:
	ice_dpll_deinit_direct_pins(cgu, pf->dplls.outputs,
				    pf->dplls.num_outputs,
				    &ice_dpll_output_ops, pf->dplls.pps.dpll,
				    pf->dplls.eec.dpll);
deinit_inputs:
	ice_dpll_deinit_direct_pins(cgu, pf->dplls.inputs, pf->dplls.num_inputs,
				    &ice_dpll_input_ops, pf->dplls.pps.dpll,
				    pf->dplls.eec.dpll);
	return ret;
}

/**
 * ice_dpll_deinit_dpll - deinitialize dpll device
 * @pf: board private structure
 * @d: pointer to ice_dpll
 * @cgu: if cgu is present and controlled by this NIC
 *
 * If cgu is owned unregister the dpll from dpll subsystem.
 * Release resources of dpll device from dpll subsystem.
 */
static void
ice_dpll_deinit_dpll(struct ice_pf *pf, struct ice_dpll *d, bool cgu)
{
	if (cgu)
		dpll_device_unregister(d->dpll, d->ops, d);
	dpll_device_put(d->dpll);
}

/**
 * ice_dpll_init_dpll - initialize dpll device in dpll subsystem
 * @pf: board private structure
 * @d: dpll to be initialized
 * @cgu: if cgu is present and controlled by this NIC
 * @type: type of dpll being initialized
 *
 * Allocate dpll instance for this board in dpll subsystem, if cgu is controlled
 * by this NIC, register dpll with the callback ops.
 *
 * Return:
 * * 0 - success
 * * negative - initialization failure reason
 */
static int
ice_dpll_init_dpll(struct ice_pf *pf, struct ice_dpll *d, bool cgu,
		   enum dpll_type type)
{
	u64 clock_id = pf->dplls.clock_id;
	int ret;

	d->dpll = dpll_device_get(clock_id, d->dpll_idx, THIS_MODULE);
	if (IS_ERR(d->dpll)) {
		ret = PTR_ERR(d->dpll);
		dev_err(ice_pf_to_dev(pf),
			"dpll_device_get failed (%p) err=%d\n", d, ret);
		return ret;
	}
	d->pf = pf;
	if (cgu) {
		const struct dpll_device_ops *ops = &ice_dpll_ops;

		if (type == DPLL_TYPE_PPS && ice_dpll_is_pps_phase_monitor(pf))
			ops =  &ice_dpll_pom_ops;
		ice_dpll_update_state(pf, d, true);
		ret = dpll_device_register(d->dpll, type, ops, d);
		if (ret) {
			dpll_device_put(d->dpll);
			return ret;
		}
		d->ops = ops;
	}

	return 0;
}

/**
 * ice_dpll_deinit_worker - deinitialize dpll kworker
 * @pf: board private structure
 *
 * Stop dpll's kworker, release it's resources.
 */
static void ice_dpll_deinit_worker(struct ice_pf *pf)
{
	struct ice_dplls *d = &pf->dplls;

	kthread_cancel_delayed_work_sync(&d->work);
	kthread_destroy_worker(d->kworker);
}

/**
 * ice_dpll_init_worker - Initialize DPLLs periodic worker
 * @pf: board private structure
 *
 * Create and start DPLLs periodic worker.
 *
 * Context: Shall be called after pf->dplls.lock is initialized.
 * Return:
 * * 0 - success
 * * negative - create worker failure
 */
static int ice_dpll_init_worker(struct ice_pf *pf)
{
	struct ice_dplls *d = &pf->dplls;
	struct kthread_worker *kworker;

	kthread_init_delayed_work(&d->work, ice_dpll_periodic_work);
	kworker = kthread_run_worker(0, "ice-dplls-%s",
					dev_name(ice_pf_to_dev(pf)));
	if (IS_ERR(kworker))
		return PTR_ERR(kworker);
	d->kworker = kworker;
	d->cgu_state_acq_err_num = 0;
	kthread_queue_delayed_work(d->kworker, &d->work, 0);

	return 0;
}

/**
 * ice_dpll_phase_range_set - initialize phase adjust range helper
 * @range: pointer to phase adjust range struct to be initialized
 * @phase_adj: a value to be used as min(-)/max(+) boundary
 */
static void ice_dpll_phase_range_set(struct dpll_pin_phase_adjust_range *range,
				     u32 phase_adj)
{
	range->min = -phase_adj;
	range->max = phase_adj;
}

/**
 * ice_dpll_init_info_pins_generic - initializes generic pins info
 * @pf: board private structure
 * @input: if input pins initialized
 *
 * Init information for generic pins, cache them in PF's pins structures.
 *
 * Return:
 * * 0 - success
 * * negative - init failure reason
 */
static int ice_dpll_init_info_pins_generic(struct ice_pf *pf, bool input)
{
	struct ice_dpll *de = &pf->dplls.eec, *dp = &pf->dplls.pps;
	static const char labels[][sizeof("99")] = {
		"0", "1", "2", "3", "4", "5", "6", "7", "8",
		"9", "10", "11", "12", "13", "14", "15" };
	u32 cap = DPLL_PIN_CAPABILITIES_STATE_CAN_CHANGE;
	enum ice_dpll_pin_type pin_type;
	int i, pin_num, ret = -EINVAL;
	struct ice_dpll_pin *pins;
	u32 phase_adj_max;

	if (input) {
		pin_num = pf->dplls.num_inputs;
		pins = pf->dplls.inputs;
		phase_adj_max = pf->dplls.input_phase_adj_max;
		pin_type = ICE_DPLL_PIN_TYPE_INPUT;
		cap |= DPLL_PIN_CAPABILITIES_PRIORITY_CAN_CHANGE;
	} else {
		pin_num = pf->dplls.num_outputs;
		pins = pf->dplls.outputs;
		phase_adj_max = pf->dplls.output_phase_adj_max;
		pin_type = ICE_DPLL_PIN_TYPE_OUTPUT;
	}
	if (pin_num > ARRAY_SIZE(labels))
		return ret;

	for (i = 0; i < pin_num; i++) {
		pins[i].idx = i;
		pins[i].prop.board_label = labels[i];
		ice_dpll_phase_range_set(&pins[i].prop.phase_range,
					 phase_adj_max);
		pins[i].prop.capabilities = cap;
		pins[i].pf = pf;
		ret = ice_dpll_pin_state_update(pf, &pins[i], pin_type, NULL);
		if (ret)
			break;
		if (input && pins[i].freq == ICE_DPLL_PIN_GEN_RCLK_FREQ)
			pins[i].prop.type = DPLL_PIN_TYPE_MUX;
		else
			pins[i].prop.type = DPLL_PIN_TYPE_EXT;
		if (!input)
			continue;
		ret = ice_aq_get_cgu_ref_prio(&pf->hw, de->dpll_idx, i,
					      &de->input_prio[i]);
		if (ret)
			break;
		ret = ice_aq_get_cgu_ref_prio(&pf->hw, dp->dpll_idx, i,
					      &dp->input_prio[i]);
		if (ret)
			break;
	}

	return ret;
}

/**
 * ice_dpll_init_info_direct_pins - initializes direct pins info
 * @pf: board private structure
 * @pin_type: type of pins being initialized
 *
 * Init information for directly connected pins, cache them in pf's pins
 * structures.
 *
 * Return:
 * * 0 - success
 * * negative - init failure reason
 */
static int
ice_dpll_init_info_direct_pins(struct ice_pf *pf,
			       enum ice_dpll_pin_type pin_type)
{
	struct ice_dpll *de = &pf->dplls.eec, *dp = &pf->dplls.pps;
	int num_pins, i, ret = -EINVAL;
	struct ice_hw *hw = &pf->hw;
	struct ice_dpll_pin *pins;
	unsigned long caps;
	u32 phase_adj_max;
	u8 freq_supp_num;
	bool input;

	switch (pin_type) {
	case ICE_DPLL_PIN_TYPE_INPUT:
		pins = pf->dplls.inputs;
		num_pins = pf->dplls.num_inputs;
		phase_adj_max = pf->dplls.input_phase_adj_max;
		input = true;
		break;
	case ICE_DPLL_PIN_TYPE_OUTPUT:
		pins = pf->dplls.outputs;
		num_pins = pf->dplls.num_outputs;
		phase_adj_max = pf->dplls.output_phase_adj_max;
		input = false;
		break;
	default:
		return -EINVAL;
	}
	if (num_pins != ice_cgu_get_num_pins(hw, input)) {
		pf->dplls.generic = true;
		return ice_dpll_init_info_pins_generic(pf, input);
	}

	for (i = 0; i < num_pins; i++) {
		caps = 0;
		pins[i].idx = i;
		pins[i].prop.board_label = ice_cgu_get_pin_name(hw, i, input);
		pins[i].prop.type = ice_cgu_get_pin_type(hw, i, input);
		if (input) {
			ret = ice_aq_get_cgu_ref_prio(hw, de->dpll_idx, i,
						      &de->input_prio[i]);
			if (ret)
				return ret;
			ret = ice_aq_get_cgu_ref_prio(hw, dp->dpll_idx, i,
						      &dp->input_prio[i]);
			if (ret)
				return ret;
			caps |= (DPLL_PIN_CAPABILITIES_PRIORITY_CAN_CHANGE |
				 DPLL_PIN_CAPABILITIES_STATE_CAN_CHANGE);
			if (ice_dpll_is_sw_pin(pf, i, true))
				pins[i].hidden = true;
		} else {
			ret = ice_cgu_get_output_pin_state_caps(hw, i, &caps);
			if (ret)
				return ret;
			if (ice_dpll_is_sw_pin(pf, i, false))
				pins[i].hidden = true;
		}
		ice_dpll_phase_range_set(&pins[i].prop.phase_range,
					 phase_adj_max);
		pins[i].prop.capabilities = caps;
		ret = ice_dpll_pin_state_update(pf, &pins[i], pin_type, NULL);
		if (ret)
			return ret;
		pins[i].prop.freq_supported =
			ice_cgu_get_pin_freq_supp(hw, i, input, &freq_supp_num);
		pins[i].prop.freq_supported_num = freq_supp_num;
		pins[i].pf = pf;
	}
	if (input)
		ret = ice_dpll_init_ref_sync_inputs(pf);

	return ret;
}

/**
 * ice_dpll_init_info_rclk_pin - initializes rclk pin information
 * @pf: board private structure
 *
 * Init information for rclk pin, cache them in pf->dplls.rclk.
 *
 * Return:
 * * 0 - success
 * * negative - init failure reason
 */
static int ice_dpll_init_info_rclk_pin(struct ice_pf *pf)
{
	struct ice_dpll_pin *pin = &pf->dplls.rclk;

	pin->prop.type = DPLL_PIN_TYPE_SYNCE_ETH_PORT;
	pin->prop.capabilities |= DPLL_PIN_CAPABILITIES_STATE_CAN_CHANGE;
	pin->pf = pf;

	return ice_dpll_pin_state_update(pf, pin,
					 ICE_DPLL_PIN_TYPE_RCLK_INPUT, NULL);
}

/**
 * ice_dpll_init_info_sw_pins - initializes software controlled pin information
 * @pf: board private structure
 *
 * Init information for software controlled pins, cache them in
 * pf->dplls.sma and pf->dplls.ufl.
 *
 * Return:
 * * 0 - success
 * * negative - init failure reason
 */
static int ice_dpll_init_info_sw_pins(struct ice_pf *pf)
{
	u8 freq_supp_num, pin_abs_idx, input_idx_offset = 0;
	struct ice_dplls *d = &pf->dplls;
	struct ice_dpll_pin *pin;
	u32 phase_adj_max, caps;
	int i, ret;

	if (pf->hw.device_id == ICE_DEV_ID_E810C_QSFP)
		input_idx_offset = ICE_E810_RCLK_PINS_NUM;
	phase_adj_max = max(d->input_phase_adj_max, d->output_phase_adj_max);
	caps = DPLL_PIN_CAPABILITIES_STATE_CAN_CHANGE;
	for (i = 0; i < ICE_DPLL_PIN_SW_NUM; i++) {
		pin = &d->sma[i];
		pin->idx = i;
		pin->prop.type = DPLL_PIN_TYPE_EXT;
		pin_abs_idx = ICE_DPLL_PIN_SW_INPUT_ABS(i) + input_idx_offset;
		pin->prop.freq_supported =
			ice_cgu_get_pin_freq_supp(&pf->hw, pin_abs_idx,
						  true, &freq_supp_num);
		pin->prop.freq_supported_num = freq_supp_num;
		pin->prop.capabilities =
			(DPLL_PIN_CAPABILITIES_DIRECTION_CAN_CHANGE |
			 DPLL_PIN_CAPABILITIES_PRIORITY_CAN_CHANGE |
			 caps);
		pin->pf = pf;
		pin->prop.board_label = ice_dpll_sw_pin_sma[i];
		pin->input = &d->inputs[pin_abs_idx];
		if (pin->input->ref_sync)
			pin->ref_sync = pin->input->ref_sync - pin_abs_idx;
		pin->output = &d->outputs[ICE_DPLL_PIN_SW_OUTPUT_ABS(i)];
		ice_dpll_phase_range_set(&pin->prop.phase_range, phase_adj_max);
	}
	for (i = 0; i < ICE_DPLL_PIN_SW_NUM; i++) {
		pin = &d->ufl[i];
		pin->idx = i;
		pin->prop.type = DPLL_PIN_TYPE_EXT;
		pin->prop.capabilities = caps;
		pin->pf = pf;
		pin->prop.board_label = ice_dpll_sw_pin_ufl[i];
		if (i == ICE_DPLL_PIN_SW_1_IDX) {
			pin->direction = DPLL_PIN_DIRECTION_OUTPUT;
			pin_abs_idx = ICE_DPLL_PIN_SW_OUTPUT_ABS(i);
			pin->prop.freq_supported =
				ice_cgu_get_pin_freq_supp(&pf->hw, pin_abs_idx,
							  false,
							  &freq_supp_num);
			pin->prop.freq_supported_num = freq_supp_num;
			pin->input = NULL;
			pin->output = &d->outputs[pin_abs_idx];
		} else if (i == ICE_DPLL_PIN_SW_2_IDX) {
			pin->direction = DPLL_PIN_DIRECTION_INPUT;
			pin_abs_idx = ICE_DPLL_PIN_SW_INPUT_ABS(i) +
				      input_idx_offset;
			pin->output = NULL;
			pin->input = &d->inputs[pin_abs_idx];
			pin->prop.freq_supported =
				ice_cgu_get_pin_freq_supp(&pf->hw, pin_abs_idx,
							  true, &freq_supp_num);
			pin->prop.freq_supported_num = freq_supp_num;
			pin->prop.capabilities =
				(DPLL_PIN_CAPABILITIES_PRIORITY_CAN_CHANGE |
				 caps);
		}
		ice_dpll_phase_range_set(&pin->prop.phase_range, phase_adj_max);
	}
	ret = ice_dpll_pin_state_update(pf, pin, ICE_DPLL_PIN_TYPE_SOFTWARE,
					NULL);
	if (ret)
		return ret;

	return 0;
}

/**
 * ice_dpll_init_pins_info - init pins info wrapper
 * @pf: board private structure
 * @pin_type: type of pins being initialized
 *
 * Wraps functions for pin initialization.
 *
 * Return:
 * * 0 - success
 * * negative - init failure reason
 */
static int
ice_dpll_init_pins_info(struct ice_pf *pf, enum ice_dpll_pin_type pin_type)
{
	switch (pin_type) {
	case ICE_DPLL_PIN_TYPE_INPUT:
	case ICE_DPLL_PIN_TYPE_OUTPUT:
		return ice_dpll_init_info_direct_pins(pf, pin_type);
	case ICE_DPLL_PIN_TYPE_RCLK_INPUT:
		return ice_dpll_init_info_rclk_pin(pf);
	case ICE_DPLL_PIN_TYPE_SOFTWARE:
		return ice_dpll_init_info_sw_pins(pf);
	default:
		return -EINVAL;
	}
}

/**
 * ice_dpll_deinit_info - release memory allocated for pins info
 * @pf: board private structure
 *
 * Release memory allocated for pins by ice_dpll_init_info function.
 */
static void ice_dpll_deinit_info(struct ice_pf *pf)
{
	kfree(pf->dplls.inputs);
	kfree(pf->dplls.outputs);
	kfree(pf->dplls.eec.input_prio);
	kfree(pf->dplls.pps.input_prio);
}

/**
 * ice_dpll_init_info - prepare pf's dpll information structure
 * @pf: board private structure
 * @cgu: if cgu is present and controlled by this NIC
 *
 * Acquire (from HW) and set basic dpll information (on pf->dplls struct).
 *
 * Return:
 * * 0 - success
 * * negative - init failure reason
 */
static int ice_dpll_init_info(struct ice_pf *pf, bool cgu)
{
	struct ice_aqc_get_cgu_abilities abilities;
	struct ice_dpll *de = &pf->dplls.eec;
	struct ice_dpll *dp = &pf->dplls.pps;
	struct ice_dplls *d = &pf->dplls;
	struct ice_hw *hw = &pf->hw;
	int ret, alloc_size, i;

	d->clock_id = ice_generate_clock_id(pf);
	ret = ice_aq_get_cgu_abilities(hw, &abilities);
	if (ret) {
		dev_err(ice_pf_to_dev(pf),
			"err:%d %s failed to read cgu abilities\n",
			ret, libie_aq_str(hw->adminq.sq_last_status));
		return ret;
	}

	de->dpll_idx = abilities.eec_dpll_idx;
	dp->dpll_idx = abilities.pps_dpll_idx;
	d->num_inputs = abilities.num_inputs;
	d->num_outputs = abilities.num_outputs;
	d->input_phase_adj_max = le32_to_cpu(abilities.max_in_phase_adj) &
		ICE_AQC_GET_CGU_MAX_PHASE_ADJ;
	d->output_phase_adj_max = le32_to_cpu(abilities.max_out_phase_adj) &
		ICE_AQC_GET_CGU_MAX_PHASE_ADJ;

	alloc_size = sizeof(*d->inputs) * d->num_inputs;
	d->inputs = kzalloc(alloc_size, GFP_KERNEL);
	if (!d->inputs)
		return -ENOMEM;

	alloc_size = sizeof(*de->input_prio) * d->num_inputs;
	de->input_prio = kzalloc(alloc_size, GFP_KERNEL);
	if (!de->input_prio)
		return -ENOMEM;

	dp->input_prio = kzalloc(alloc_size, GFP_KERNEL);
	if (!dp->input_prio)
		return -ENOMEM;

	ret = ice_dpll_init_pins_info(pf, ICE_DPLL_PIN_TYPE_INPUT);
	if (ret)
		goto deinit_info;

	if (cgu) {
		alloc_size = sizeof(*d->outputs) * d->num_outputs;
		d->outputs = kzalloc(alloc_size, GFP_KERNEL);
		if (!d->outputs) {
			ret = -ENOMEM;
			goto deinit_info;
		}

		ret = ice_dpll_init_pins_info(pf, ICE_DPLL_PIN_TYPE_OUTPUT);
		if (ret)
			goto deinit_info;
		ret = ice_dpll_init_pins_info(pf, ICE_DPLL_PIN_TYPE_SOFTWARE);
		if (ret)
			goto deinit_info;
	}

	ret = ice_get_cgu_rclk_pin_info(&pf->hw, &d->base_rclk_idx,
					&pf->dplls.rclk.num_parents);
	if (ret)
		return ret;
	for (i = 0; i < pf->dplls.rclk.num_parents; i++)
		pf->dplls.rclk.parent_idx[i] = d->base_rclk_idx + i;
	ret = ice_dpll_init_pins_info(pf, ICE_DPLL_PIN_TYPE_RCLK_INPUT);
	if (ret)
		return ret;
	de->mode = DPLL_MODE_AUTOMATIC;
	dp->mode = DPLL_MODE_AUTOMATIC;

	dev_dbg(ice_pf_to_dev(pf),
		"%s - success, inputs:%u, outputs:%u rclk-parents:%u\n",
		__func__, d->num_inputs, d->num_outputs, d->rclk.num_parents);

	return 0;

deinit_info:
	dev_err(ice_pf_to_dev(pf),
		"%s - fail: d->inputs:%p, de->input_prio:%p, dp->input_prio:%p, d->outputs:%p\n",
		__func__, d->inputs, de->input_prio,
		dp->input_prio, d->outputs);
	ice_dpll_deinit_info(pf);
	return ret;
}

/**
 * ice_dpll_deinit - Disable the driver/HW support for dpll subsystem
 * the dpll device.
 * @pf: board private structure
 *
 * Handles the cleanup work required after dpll initialization, freeing
 * resources and unregistering the dpll, pin and all resources used for
 * handling them.
 *
 * Context: Destroys pf->dplls.lock mutex. Call only if ICE_FLAG_DPLL was set.
 */
void ice_dpll_deinit(struct ice_pf *pf)
{
	bool cgu = ice_is_feature_supported(pf, ICE_F_CGU);

	clear_bit(ICE_FLAG_DPLL, pf->flags);
	if (cgu)
		ice_dpll_deinit_worker(pf);

	ice_dpll_deinit_pins(pf, cgu);
	ice_dpll_deinit_dpll(pf, &pf->dplls.pps, cgu);
	ice_dpll_deinit_dpll(pf, &pf->dplls.eec, cgu);
	ice_dpll_deinit_info(pf);
	mutex_destroy(&pf->dplls.lock);
}

/**
 * ice_dpll_init - initialize support for dpll subsystem
 * @pf: board private structure
 *
 * Set up the device dplls, register them and pins connected within Linux dpll
 * subsystem. Allow userspace to obtain state of DPLL and handling of DPLL
 * configuration requests.
 *
 * Context: Initializes pf->dplls.lock mutex.
 */
void ice_dpll_init(struct ice_pf *pf)
{
	bool cgu = ice_is_feature_supported(pf, ICE_F_CGU);
	struct ice_dplls *d = &pf->dplls;
	int err = 0;

	mutex_init(&d->lock);
	err = ice_dpll_init_info(pf, cgu);
	if (err)
		goto err_exit;
	err = ice_dpll_init_dpll(pf, &pf->dplls.eec, cgu, DPLL_TYPE_EEC);
	if (err)
		goto deinit_info;
	err = ice_dpll_init_dpll(pf, &pf->dplls.pps, cgu, DPLL_TYPE_PPS);
	if (err)
		goto deinit_eec;
	err = ice_dpll_init_pins(pf, cgu);
	if (err)
		goto deinit_pps;
	if (cgu) {
		err = ice_dpll_init_worker(pf);
		if (err)
			goto deinit_pins;
	}
	set_bit(ICE_FLAG_DPLL, pf->flags);

	return;

deinit_pins:
	ice_dpll_deinit_pins(pf, cgu);
deinit_pps:
	ice_dpll_deinit_dpll(pf, &pf->dplls.pps, cgu);
deinit_eec:
	ice_dpll_deinit_dpll(pf, &pf->dplls.eec, cgu);
deinit_info:
	ice_dpll_deinit_info(pf);
err_exit:
	mutex_destroy(&d->lock);
	dev_warn(ice_pf_to_dev(pf), "DPLLs init failure err:%d\n", err);
}
