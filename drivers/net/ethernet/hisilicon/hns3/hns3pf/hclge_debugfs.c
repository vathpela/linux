// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2018-2019 Hisilicon Limited. */

#include <linux/device.h>
#include <linux/sched/clock.h>
#include <linux/string_choices.h>

#include "hclge_debugfs.h"
#include "hclge_err.h"
#include "hclge_main.h"
#include "hclge_regs.h"
#include "hclge_tm.h"
#include "hnae3.h"

#define hclge_seq_file_to_hdev(s)	\
		(((struct hnae3_ae_dev *)hnae3_seq_file_to_ae_dev(s))->priv)

static const char * const hclge_mac_state_str[] = {
	"TO_ADD", "TO_DEL", "ACTIVE"
};

static const char * const tc_map_mode_str[] = { "PRIO", "DSCP" };

static const struct hclge_dbg_dfx_message hclge_dbg_bios_common_reg[] = {
	{false, "Reserved"},
	{true,	"BP_CPU_STATE"},
	{true,	"DFX_MSIX_INFO_NIC_0"},
	{true,	"DFX_MSIX_INFO_NIC_1"},
	{true,	"DFX_MSIX_INFO_NIC_2"},
	{true,	"DFX_MSIX_INFO_NIC_3"},

	{true,	"DFX_MSIX_INFO_ROC_0"},
	{true,	"DFX_MSIX_INFO_ROC_1"},
	{true,	"DFX_MSIX_INFO_ROC_2"},
	{true,	"DFX_MSIX_INFO_ROC_3"},
	{false, "Reserved"},
	{false, "Reserved"},
};

static const struct hclge_dbg_dfx_message hclge_dbg_ssu_reg_0[] = {
	{false, "Reserved"},
	{true,	"SSU_ETS_PORT_STATUS"},
	{true,	"SSU_ETS_TCG_STATUS"},
	{false, "Reserved"},
	{false, "Reserved"},
	{true,	"SSU_BP_STATUS_0"},

	{true,	"SSU_BP_STATUS_1"},
	{true,	"SSU_BP_STATUS_2"},
	{true,	"SSU_BP_STATUS_3"},
	{true,	"SSU_BP_STATUS_4"},
	{true,	"SSU_BP_STATUS_5"},
	{true,	"SSU_MAC_TX_PFC_IND"},

	{true,	"MAC_SSU_RX_PFC_IND"},
	{true,	"BTMP_AGEING_ST_B0"},
	{true,	"BTMP_AGEING_ST_B1"},
	{true,	"BTMP_AGEING_ST_B2"},
	{false, "Reserved"},
	{false, "Reserved"},

	{true,	"FULL_DROP_NUM"},
	{true,	"PART_DROP_NUM"},
	{true,	"PPP_KEY_DROP_NUM"},
	{true,	"PPP_RLT_DROP_NUM"},
	{true,	"LO_PRI_UNICAST_RLT_DROP_NUM"},
	{true,	"HI_PRI_MULTICAST_RLT_DROP_NUM"},

	{true,	"LO_PRI_MULTICAST_RLT_DROP_NUM"},
	{true,	"NCSI_PACKET_CURR_BUFFER_CNT"},
	{true,	"BTMP_AGEING_RLS_CNT_BANK0"},
	{true,	"BTMP_AGEING_RLS_CNT_BANK1"},
	{true,	"BTMP_AGEING_RLS_CNT_BANK2"},
	{true,	"SSU_MB_RD_RLT_DROP_CNT"},

	{true,	"SSU_PPP_MAC_KEY_NUM_L"},
	{true,	"SSU_PPP_MAC_KEY_NUM_H"},
	{true,	"SSU_PPP_HOST_KEY_NUM_L"},
	{true,	"SSU_PPP_HOST_KEY_NUM_H"},
	{true,	"PPP_SSU_MAC_RLT_NUM_L"},
	{true,	"PPP_SSU_MAC_RLT_NUM_H"},

	{true,	"PPP_SSU_HOST_RLT_NUM_L"},
	{true,	"PPP_SSU_HOST_RLT_NUM_H"},
	{true,	"NCSI_RX_PACKET_IN_CNT_L"},
	{true,	"NCSI_RX_PACKET_IN_CNT_H"},
	{true,	"NCSI_TX_PACKET_OUT_CNT_L"},
	{true,	"NCSI_TX_PACKET_OUT_CNT_H"},

	{true,	"SSU_KEY_DROP_NUM"},
	{true,	"MB_UNCOPY_NUM"},
	{true,	"RX_OQ_DROP_PKT_CNT"},
	{true,	"TX_OQ_DROP_PKT_CNT"},
	{true,	"BANK_UNBALANCE_DROP_CNT"},
	{true,	"BANK_UNBALANCE_RX_DROP_CNT"},

	{true,	"NIC_L2_ERR_DROP_PKT_CNT"},
	{true,	"ROC_L2_ERR_DROP_PKT_CNT"},
	{true,	"NIC_L2_ERR_DROP_PKT_CNT_RX"},
	{true,	"ROC_L2_ERR_DROP_PKT_CNT_RX"},
	{true,	"RX_OQ_GLB_DROP_PKT_CNT"},
	{false, "Reserved"},

	{true,	"LO_PRI_UNICAST_CUR_CNT"},
	{true,	"HI_PRI_MULTICAST_CUR_CNT"},
	{true,	"LO_PRI_MULTICAST_CUR_CNT"},
	{false, "Reserved"},
	{false, "Reserved"},
	{false, "Reserved"},
};

static const struct hclge_dbg_dfx_message hclge_dbg_ssu_reg_1[] = {
	{true,	"prt_id"},
	{true,	"PACKET_TC_CURR_BUFFER_CNT_0"},
	{true,	"PACKET_TC_CURR_BUFFER_CNT_1"},
	{true,	"PACKET_TC_CURR_BUFFER_CNT_2"},
	{true,	"PACKET_TC_CURR_BUFFER_CNT_3"},
	{true,	"PACKET_TC_CURR_BUFFER_CNT_4"},

	{true,	"PACKET_TC_CURR_BUFFER_CNT_5"},
	{true,	"PACKET_TC_CURR_BUFFER_CNT_6"},
	{true,	"PACKET_TC_CURR_BUFFER_CNT_7"},
	{true,	"PACKET_CURR_BUFFER_CNT"},
	{false, "Reserved"},
	{false, "Reserved"},

	{true,	"RX_PACKET_IN_CNT_L"},
	{true,	"RX_PACKET_IN_CNT_H"},
	{true,	"RX_PACKET_OUT_CNT_L"},
	{true,	"RX_PACKET_OUT_CNT_H"},
	{true,	"TX_PACKET_IN_CNT_L"},
	{true,	"TX_PACKET_IN_CNT_H"},

	{true,	"TX_PACKET_OUT_CNT_L"},
	{true,	"TX_PACKET_OUT_CNT_H"},
	{true,	"ROC_RX_PACKET_IN_CNT_L"},
	{true,	"ROC_RX_PACKET_IN_CNT_H"},
	{true,	"ROC_TX_PACKET_OUT_CNT_L"},
	{true,	"ROC_TX_PACKET_OUT_CNT_H"},

	{true,	"RX_PACKET_TC_IN_CNT_0_L"},
	{true,	"RX_PACKET_TC_IN_CNT_0_H"},
	{true,	"RX_PACKET_TC_IN_CNT_1_L"},
	{true,	"RX_PACKET_TC_IN_CNT_1_H"},
	{true,	"RX_PACKET_TC_IN_CNT_2_L"},
	{true,	"RX_PACKET_TC_IN_CNT_2_H"},

	{true,	"RX_PACKET_TC_IN_CNT_3_L"},
	{true,	"RX_PACKET_TC_IN_CNT_3_H"},
	{true,	"RX_PACKET_TC_IN_CNT_4_L"},
	{true,	"RX_PACKET_TC_IN_CNT_4_H"},
	{true,	"RX_PACKET_TC_IN_CNT_5_L"},
	{true,	"RX_PACKET_TC_IN_CNT_5_H"},

	{true,	"RX_PACKET_TC_IN_CNT_6_L"},
	{true,	"RX_PACKET_TC_IN_CNT_6_H"},
	{true,	"RX_PACKET_TC_IN_CNT_7_L"},
	{true,	"RX_PACKET_TC_IN_CNT_7_H"},
	{true,	"RX_PACKET_TC_OUT_CNT_0_L"},
	{true,	"RX_PACKET_TC_OUT_CNT_0_H"},

	{true,	"RX_PACKET_TC_OUT_CNT_1_L"},
	{true,	"RX_PACKET_TC_OUT_CNT_1_H"},
	{true,	"RX_PACKET_TC_OUT_CNT_2_L"},
	{true,	"RX_PACKET_TC_OUT_CNT_2_H"},
	{true,	"RX_PACKET_TC_OUT_CNT_3_L"},
	{true,	"RX_PACKET_TC_OUT_CNT_3_H"},

	{true,	"RX_PACKET_TC_OUT_CNT_4_L"},
	{true,	"RX_PACKET_TC_OUT_CNT_4_H"},
	{true,	"RX_PACKET_TC_OUT_CNT_5_L"},
	{true,	"RX_PACKET_TC_OUT_CNT_5_H"},
	{true,	"RX_PACKET_TC_OUT_CNT_6_L"},
	{true,	"RX_PACKET_TC_OUT_CNT_6_H"},

	{true,	"RX_PACKET_TC_OUT_CNT_7_L"},
	{true,	"RX_PACKET_TC_OUT_CNT_7_H"},
	{true,	"TX_PACKET_TC_IN_CNT_0_L"},
	{true,	"TX_PACKET_TC_IN_CNT_0_H"},
	{true,	"TX_PACKET_TC_IN_CNT_1_L"},
	{true,	"TX_PACKET_TC_IN_CNT_1_H"},

	{true,	"TX_PACKET_TC_IN_CNT_2_L"},
	{true,	"TX_PACKET_TC_IN_CNT_2_H"},
	{true,	"TX_PACKET_TC_IN_CNT_3_L"},
	{true,	"TX_PACKET_TC_IN_CNT_3_H"},
	{true,	"TX_PACKET_TC_IN_CNT_4_L"},
	{true,	"TX_PACKET_TC_IN_CNT_4_H"},

	{true,	"TX_PACKET_TC_IN_CNT_5_L"},
	{true,	"TX_PACKET_TC_IN_CNT_5_H"},
	{true,	"TX_PACKET_TC_IN_CNT_6_L"},
	{true,	"TX_PACKET_TC_IN_CNT_6_H"},
	{true,	"TX_PACKET_TC_IN_CNT_7_L"},
	{true,	"TX_PACKET_TC_IN_CNT_7_H"},

	{true,	"TX_PACKET_TC_OUT_CNT_0_L"},
	{true,	"TX_PACKET_TC_OUT_CNT_0_H"},
	{true,	"TX_PACKET_TC_OUT_CNT_1_L"},
	{true,	"TX_PACKET_TC_OUT_CNT_1_H"},
	{true,	"TX_PACKET_TC_OUT_CNT_2_L"},
	{true,	"TX_PACKET_TC_OUT_CNT_2_H"},

	{true,	"TX_PACKET_TC_OUT_CNT_3_L"},
	{true,	"TX_PACKET_TC_OUT_CNT_3_H"},
	{true,	"TX_PACKET_TC_OUT_CNT_4_L"},
	{true,	"TX_PACKET_TC_OUT_CNT_4_H"},
	{true,	"TX_PACKET_TC_OUT_CNT_5_L"},
	{true,	"TX_PACKET_TC_OUT_CNT_5_H"},

	{true,	"TX_PACKET_TC_OUT_CNT_6_L"},
	{true,	"TX_PACKET_TC_OUT_CNT_6_H"},
	{true,	"TX_PACKET_TC_OUT_CNT_7_L"},
	{true,	"TX_PACKET_TC_OUT_CNT_7_H"},
	{false, "Reserved"},
	{false, "Reserved"},
};

static const struct hclge_dbg_dfx_message hclge_dbg_ssu_reg_2[] = {
	{true,	"OQ_INDEX"},
	{true,	"QUEUE_CNT"},
	{false, "Reserved"},
	{false, "Reserved"},
	{false, "Reserved"},
	{false, "Reserved"},
};

static const struct hclge_dbg_dfx_message hclge_dbg_igu_egu_reg[] = {
	{true,	"prt_id"},
	{true,	"IGU_RX_ERR_PKT"},
	{true,	"IGU_RX_NO_SOF_PKT"},
	{true,	"EGU_TX_1588_SHORT_PKT"},
	{true,	"EGU_TX_1588_PKT"},
	{true,	"EGU_TX_ERR_PKT"},

	{true,	"IGU_RX_OUT_L2_PKT"},
	{true,	"IGU_RX_OUT_L3_PKT"},
	{true,	"IGU_RX_OUT_L4_PKT"},
	{true,	"IGU_RX_IN_L2_PKT"},
	{true,	"IGU_RX_IN_L3_PKT"},
	{true,	"IGU_RX_IN_L4_PKT"},

	{true,	"IGU_RX_EL3E_PKT"},
	{true,	"IGU_RX_EL4E_PKT"},
	{true,	"IGU_RX_L3E_PKT"},
	{true,	"IGU_RX_L4E_PKT"},
	{true,	"IGU_RX_ROCEE_PKT"},
	{true,	"IGU_RX_OUT_UDP0_PKT"},

	{true,	"IGU_RX_IN_UDP0_PKT"},
	{true,	"IGU_MC_CAR_DROP_PKT_L"},
	{true,	"IGU_MC_CAR_DROP_PKT_H"},
	{true,	"IGU_BC_CAR_DROP_PKT_L"},
	{true,	"IGU_BC_CAR_DROP_PKT_H"},
	{false, "Reserved"},

	{true,	"IGU_RX_OVERSIZE_PKT_L"},
	{true,	"IGU_RX_OVERSIZE_PKT_H"},
	{true,	"IGU_RX_UNDERSIZE_PKT_L"},
	{true,	"IGU_RX_UNDERSIZE_PKT_H"},
	{true,	"IGU_RX_OUT_ALL_PKT_L"},
	{true,	"IGU_RX_OUT_ALL_PKT_H"},

	{true,	"IGU_TX_OUT_ALL_PKT_L"},
	{true,	"IGU_TX_OUT_ALL_PKT_H"},
	{true,	"IGU_RX_UNI_PKT_L"},
	{true,	"IGU_RX_UNI_PKT_H"},
	{true,	"IGU_RX_MULTI_PKT_L"},
	{true,	"IGU_RX_MULTI_PKT_H"},

	{true,	"IGU_RX_BROAD_PKT_L"},
	{true,	"IGU_RX_BROAD_PKT_H"},
	{true,	"EGU_TX_OUT_ALL_PKT_L"},
	{true,	"EGU_TX_OUT_ALL_PKT_H"},
	{true,	"EGU_TX_UNI_PKT_L"},
	{true,	"EGU_TX_UNI_PKT_H"},

	{true,	"EGU_TX_MULTI_PKT_L"},
	{true,	"EGU_TX_MULTI_PKT_H"},
	{true,	"EGU_TX_BROAD_PKT_L"},
	{true,	"EGU_TX_BROAD_PKT_H"},
	{true,	"IGU_TX_KEY_NUM_L"},
	{true,	"IGU_TX_KEY_NUM_H"},

	{true,	"IGU_RX_NON_TUN_PKT_L"},
	{true,	"IGU_RX_NON_TUN_PKT_H"},
	{true,	"IGU_RX_TUN_PKT_L"},
	{true,	"IGU_RX_TUN_PKT_H"},
	{false,	"Reserved"},
	{false,	"Reserved"},
};

static const struct hclge_dbg_dfx_message hclge_dbg_rpu_reg_0[] = {
	{true, "tc_queue_num"},
	{true, "FSM_DFX_ST0"},
	{true, "FSM_DFX_ST1"},
	{true, "RPU_RX_PKT_DROP_CNT"},
	{true, "BUF_WAIT_TIMEOUT"},
	{true, "BUF_WAIT_TIMEOUT_QID"},
};

static const struct hclge_dbg_dfx_message hclge_dbg_rpu_reg_1[] = {
	{false, "Reserved"},
	{true,	"FIFO_DFX_ST0"},
	{true,	"FIFO_DFX_ST1"},
	{true,	"FIFO_DFX_ST2"},
	{true,	"FIFO_DFX_ST3"},
	{true,	"FIFO_DFX_ST4"},

	{true,	"FIFO_DFX_ST5"},
	{false, "Reserved"},
	{false, "Reserved"},
	{false, "Reserved"},
	{false, "Reserved"},
	{false, "Reserved"},
};

static const struct hclge_dbg_dfx_message hclge_dbg_ncsi_reg[] = {
	{false, "Reserved"},
	{true,	"NCSI_EGU_TX_FIFO_STS"},
	{true,	"NCSI_PAUSE_STATUS"},
	{true,	"NCSI_RX_CTRL_DMAC_ERR_CNT"},
	{true,	"NCSI_RX_CTRL_SMAC_ERR_CNT"},
	{true,	"NCSI_RX_CTRL_CKS_ERR_CNT"},

	{true,	"NCSI_RX_CTRL_PKT_CNT"},
	{true,	"NCSI_RX_PT_DMAC_ERR_CNT"},
	{true,	"NCSI_RX_PT_SMAC_ERR_CNT"},
	{true,	"NCSI_RX_PT_PKT_CNT"},
	{true,	"NCSI_RX_FCS_ERR_CNT"},
	{true,	"NCSI_TX_CTRL_DMAC_ERR_CNT"},

	{true,	"NCSI_TX_CTRL_SMAC_ERR_CNT"},
	{true,	"NCSI_TX_CTRL_PKT_CNT"},
	{true,	"NCSI_TX_PT_DMAC_ERR_CNT"},
	{true,	"NCSI_TX_PT_SMAC_ERR_CNT"},
	{true,	"NCSI_TX_PT_PKT_CNT"},
	{true,	"NCSI_TX_PT_PKT_TRUNC_CNT"},

	{true,	"NCSI_TX_PT_PKT_ERR_CNT"},
	{true,	"NCSI_TX_CTRL_PKT_ERR_CNT"},
	{true,	"NCSI_RX_CTRL_PKT_TRUNC_CNT"},
	{true,	"NCSI_RX_CTRL_PKT_CFLIT_CNT"},
	{false, "Reserved"},
	{false, "Reserved"},

	{true,	"NCSI_MAC_RX_OCTETS_OK"},
	{true,	"NCSI_MAC_RX_OCTETS_BAD"},
	{true,	"NCSI_MAC_RX_UC_PKTS"},
	{true,	"NCSI_MAC_RX_MC_PKTS"},
	{true,	"NCSI_MAC_RX_BC_PKTS"},
	{true,	"NCSI_MAC_RX_PKTS_64OCTETS"},

	{true,	"NCSI_MAC_RX_PKTS_65TO127OCTETS"},
	{true,	"NCSI_MAC_RX_PKTS_128TO255OCTETS"},
	{true,	"NCSI_MAC_RX_PKTS_255TO511OCTETS"},
	{true,	"NCSI_MAC_RX_PKTS_512TO1023OCTETS"},
	{true,	"NCSI_MAC_RX_PKTS_1024TO1518OCTETS"},
	{true,	"NCSI_MAC_RX_PKTS_1519TOMAXOCTETS"},

	{true,	"NCSI_MAC_RX_FCS_ERRORS"},
	{true,	"NCSI_MAC_RX_LONG_ERRORS"},
	{true,	"NCSI_MAC_RX_JABBER_ERRORS"},
	{true,	"NCSI_MAC_RX_RUNT_ERR_CNT"},
	{true,	"NCSI_MAC_RX_SHORT_ERR_CNT"},
	{true,	"NCSI_MAC_RX_FILT_PKT_CNT"},

	{true,	"NCSI_MAC_RX_OCTETS_TOTAL_FILT"},
	{true,	"NCSI_MAC_TX_OCTETS_OK"},
	{true,	"NCSI_MAC_TX_OCTETS_BAD"},
	{true,	"NCSI_MAC_TX_UC_PKTS"},
	{true,	"NCSI_MAC_TX_MC_PKTS"},
	{true,	"NCSI_MAC_TX_BC_PKTS"},

	{true,	"NCSI_MAC_TX_PKTS_64OCTETS"},
	{true,	"NCSI_MAC_TX_PKTS_65TO127OCTETS"},
	{true,	"NCSI_MAC_TX_PKTS_128TO255OCTETS"},
	{true,	"NCSI_MAC_TX_PKTS_256TO511OCTETS"},
	{true,	"NCSI_MAC_TX_PKTS_512TO1023OCTETS"},
	{true,	"NCSI_MAC_TX_PKTS_1024TO1518OCTETS"},

	{true,	"NCSI_MAC_TX_PKTS_1519TOMAXOCTETS"},
	{true,	"NCSI_MAC_TX_UNDERRUN"},
	{true,	"NCSI_MAC_TX_CRC_ERROR"},
	{true,	"NCSI_MAC_TX_PAUSE_FRAMES"},
	{true,	"NCSI_MAC_RX_PAD_PKTS"},
	{true,	"NCSI_MAC_RX_PAUSE_FRAMES"},
};

static const struct hclge_dbg_dfx_message hclge_dbg_rtc_reg[] = {
	{false, "Reserved"},
	{true,	"LGE_IGU_AFIFO_DFX_0"},
	{true,	"LGE_IGU_AFIFO_DFX_1"},
	{true,	"LGE_IGU_AFIFO_DFX_2"},
	{true,	"LGE_IGU_AFIFO_DFX_3"},
	{true,	"LGE_IGU_AFIFO_DFX_4"},

	{true,	"LGE_IGU_AFIFO_DFX_5"},
	{true,	"LGE_IGU_AFIFO_DFX_6"},
	{true,	"LGE_IGU_AFIFO_DFX_7"},
	{true,	"LGE_EGU_AFIFO_DFX_0"},
	{true,	"LGE_EGU_AFIFO_DFX_1"},
	{true,	"LGE_EGU_AFIFO_DFX_2"},

	{true,	"LGE_EGU_AFIFO_DFX_3"},
	{true,	"LGE_EGU_AFIFO_DFX_4"},
	{true,	"LGE_EGU_AFIFO_DFX_5"},
	{true,	"LGE_EGU_AFIFO_DFX_6"},
	{true,	"LGE_EGU_AFIFO_DFX_7"},
	{true,	"CGE_IGU_AFIFO_DFX_0"},

	{true,	"CGE_IGU_AFIFO_DFX_1"},
	{true,	"CGE_EGU_AFIFO_DFX_0"},
	{true,	"CGE_EGU_AFIFO_DFX_1"},
	{false, "Reserved"},
	{false, "Reserved"},
	{false, "Reserved"},
};

static const struct hclge_dbg_dfx_message hclge_dbg_ppp_reg[] = {
	{false, "Reserved"},
	{true,	"DROP_FROM_PRT_PKT_CNT"},
	{true,	"DROP_FROM_HOST_PKT_CNT"},
	{true,	"DROP_TX_VLAN_PROC_CNT"},
	{true,	"DROP_MNG_CNT"},
	{true,	"DROP_FD_CNT"},

	{true,	"DROP_NO_DST_CNT"},
	{true,	"DROP_MC_MBID_FULL_CNT"},
	{true,	"DROP_SC_FILTERED"},
	{true,	"PPP_MC_DROP_PKT_CNT"},
	{true,	"DROP_PT_CNT"},
	{true,	"DROP_MAC_ANTI_SPOOF_CNT"},

	{true,	"DROP_IG_VFV_CNT"},
	{true,	"DROP_IG_PRTV_CNT"},
	{true,	"DROP_CNM_PFC_PAUSE_CNT"},
	{true,	"DROP_TORUS_TC_CNT"},
	{true,	"DROP_TORUS_LPBK_CNT"},
	{true,	"PPP_HFS_STS"},

	{true,	"PPP_MC_RSLT_STS"},
	{true,	"PPP_P3U_STS"},
	{true,	"PPP_RSLT_DESCR_STS"},
	{true,	"PPP_UMV_STS_0"},
	{true,	"PPP_UMV_STS_1"},
	{true,	"PPP_VFV_STS"},

	{true,	"PPP_GRO_KEY_CNT"},
	{true,	"PPP_GRO_INFO_CNT"},
	{true,	"PPP_GRO_DROP_CNT"},
	{true,	"PPP_GRO_OUT_CNT"},
	{true,	"PPP_GRO_KEY_MATCH_DATA_CNT"},
	{true,	"PPP_GRO_KEY_MATCH_TCAM_CNT"},

	{true,	"PPP_GRO_INFO_MATCH_CNT"},
	{true,	"PPP_GRO_FREE_ENTRY_CNT"},
	{true,	"PPP_GRO_INNER_DFX_SIGNAL"},
	{false, "Reserved"},
	{false, "Reserved"},
	{false, "Reserved"},

	{true,	"GET_RX_PKT_CNT_L"},
	{true,	"GET_RX_PKT_CNT_H"},
	{true,	"GET_TX_PKT_CNT_L"},
	{true,	"GET_TX_PKT_CNT_H"},
	{true,	"SEND_UC_PRT2HOST_PKT_CNT_L"},
	{true,	"SEND_UC_PRT2HOST_PKT_CNT_H"},

	{true,	"SEND_UC_PRT2PRT_PKT_CNT_L"},
	{true,	"SEND_UC_PRT2PRT_PKT_CNT_H"},
	{true,	"SEND_UC_HOST2HOST_PKT_CNT_L"},
	{true,	"SEND_UC_HOST2HOST_PKT_CNT_H"},
	{true,	"SEND_UC_HOST2PRT_PKT_CNT_L"},
	{true,	"SEND_UC_HOST2PRT_PKT_CNT_H"},

	{true,	"SEND_MC_FROM_PRT_CNT_L"},
	{true,	"SEND_MC_FROM_PRT_CNT_H"},
	{true,	"SEND_MC_FROM_HOST_CNT_L"},
	{true,	"SEND_MC_FROM_HOST_CNT_H"},
	{true,	"SSU_MC_RD_CNT_L"},
	{true,	"SSU_MC_RD_CNT_H"},

	{true,	"SSU_MC_DROP_CNT_L"},
	{true,	"SSU_MC_DROP_CNT_H"},
	{true,	"SSU_MC_RD_PKT_CNT_L"},
	{true,	"SSU_MC_RD_PKT_CNT_H"},
	{true,	"PPP_MC_2HOST_PKT_CNT_L"},
	{true,	"PPP_MC_2HOST_PKT_CNT_H"},

	{true,	"PPP_MC_2PRT_PKT_CNT_L"},
	{true,	"PPP_MC_2PRT_PKT_CNT_H"},
	{true,	"NTSNOS_PKT_CNT_L"},
	{true,	"NTSNOS_PKT_CNT_H"},
	{true,	"NTUP_PKT_CNT_L"},
	{true,	"NTUP_PKT_CNT_H"},

	{true,	"NTLCL_PKT_CNT_L"},
	{true,	"NTLCL_PKT_CNT_H"},
	{true,	"NTTGT_PKT_CNT_L"},
	{true,	"NTTGT_PKT_CNT_H"},
	{true,	"RTNS_PKT_CNT_L"},
	{true,	"RTNS_PKT_CNT_H"},

	{true,	"RTLPBK_PKT_CNT_L"},
	{true,	"RTLPBK_PKT_CNT_H"},
	{true,	"NR_PKT_CNT_L"},
	{true,	"NR_PKT_CNT_H"},
	{true,	"RR_PKT_CNT_L"},
	{true,	"RR_PKT_CNT_H"},

	{true,	"MNG_TBL_HIT_CNT_L"},
	{true,	"MNG_TBL_HIT_CNT_H"},
	{true,	"FD_TBL_HIT_CNT_L"},
	{true,	"FD_TBL_HIT_CNT_H"},
	{true,	"FD_LKUP_CNT_L"},
	{true,	"FD_LKUP_CNT_H"},

	{true,	"BC_HIT_CNT_L"},
	{true,	"BC_HIT_CNT_H"},
	{true,	"UM_TBL_UC_HIT_CNT_L"},
	{true,	"UM_TBL_UC_HIT_CNT_H"},
	{true,	"UM_TBL_MC_HIT_CNT_L"},
	{true,	"UM_TBL_MC_HIT_CNT_H"},

	{true,	"UM_TBL_VMDQ1_HIT_CNT_L"},
	{true,	"UM_TBL_VMDQ1_HIT_CNT_H"},
	{true,	"MTA_TBL_HIT_CNT_L"},
	{true,	"MTA_TBL_HIT_CNT_H"},
	{true,	"FWD_BONDING_HIT_CNT_L"},
	{true,	"FWD_BONDING_HIT_CNT_H"},

	{true,	"PROMIS_TBL_HIT_CNT_L"},
	{true,	"PROMIS_TBL_HIT_CNT_H"},
	{true,	"GET_TUNL_PKT_CNT_L"},
	{true,	"GET_TUNL_PKT_CNT_H"},
	{true,	"GET_BMC_PKT_CNT_L"},
	{true,	"GET_BMC_PKT_CNT_H"},

	{true,	"SEND_UC_PRT2BMC_PKT_CNT_L"},
	{true,	"SEND_UC_PRT2BMC_PKT_CNT_H"},
	{true,	"SEND_UC_HOST2BMC_PKT_CNT_L"},
	{true,	"SEND_UC_HOST2BMC_PKT_CNT_H"},
	{true,	"SEND_UC_BMC2HOST_PKT_CNT_L"},
	{true,	"SEND_UC_BMC2HOST_PKT_CNT_H"},

	{true,	"SEND_UC_BMC2PRT_PKT_CNT_L"},
	{true,	"SEND_UC_BMC2PRT_PKT_CNT_H"},
	{true,	"PPP_MC_2BMC_PKT_CNT_L"},
	{true,	"PPP_MC_2BMC_PKT_CNT_H"},
	{true,	"VLAN_MIRR_CNT_L"},
	{true,	"VLAN_MIRR_CNT_H"},

	{true,	"IG_MIRR_CNT_L"},
	{true,	"IG_MIRR_CNT_H"},
	{true,	"EG_MIRR_CNT_L"},
	{true,	"EG_MIRR_CNT_H"},
	{true,	"RX_DEFAULT_HOST_HIT_CNT_L"},
	{true,	"RX_DEFAULT_HOST_HIT_CNT_H"},

	{true,	"LAN_PAIR_CNT_L"},
	{true,	"LAN_PAIR_CNT_H"},
	{true,	"UM_TBL_MC_HIT_PKT_CNT_L"},
	{true,	"UM_TBL_MC_HIT_PKT_CNT_H"},
	{true,	"MTA_TBL_HIT_PKT_CNT_L"},
	{true,	"MTA_TBL_HIT_PKT_CNT_H"},

	{true,	"PROMIS_TBL_HIT_PKT_CNT_L"},
	{true,	"PROMIS_TBL_HIT_PKT_CNT_H"},
	{false, "Reserved"},
	{false, "Reserved"},
	{false, "Reserved"},
	{false, "Reserved"},
};

static const struct hclge_dbg_dfx_message hclge_dbg_rcb_reg[] = {
	{false, "Reserved"},
	{true,	"FSM_DFX_ST0"},
	{true,	"FSM_DFX_ST1"},
	{true,	"FSM_DFX_ST2"},
	{true,	"FIFO_DFX_ST0"},
	{true,	"FIFO_DFX_ST1"},

	{true,	"FIFO_DFX_ST2"},
	{true,	"FIFO_DFX_ST3"},
	{true,	"FIFO_DFX_ST4"},
	{true,	"FIFO_DFX_ST5"},
	{true,	"FIFO_DFX_ST6"},
	{true,	"FIFO_DFX_ST7"},

	{true,	"FIFO_DFX_ST8"},
	{true,	"FIFO_DFX_ST9"},
	{true,	"FIFO_DFX_ST10"},
	{true,	"FIFO_DFX_ST11"},
	{true,	"Q_CREDIT_VLD_0"},
	{true,	"Q_CREDIT_VLD_1"},

	{true,	"Q_CREDIT_VLD_2"},
	{true,	"Q_CREDIT_VLD_3"},
	{true,	"Q_CREDIT_VLD_4"},
	{true,	"Q_CREDIT_VLD_5"},
	{true,	"Q_CREDIT_VLD_6"},
	{true,	"Q_CREDIT_VLD_7"},

	{true,	"Q_CREDIT_VLD_8"},
	{true,	"Q_CREDIT_VLD_9"},
	{true,	"Q_CREDIT_VLD_10"},
	{true,	"Q_CREDIT_VLD_11"},
	{true,	"Q_CREDIT_VLD_12"},
	{true,	"Q_CREDIT_VLD_13"},

	{true,	"Q_CREDIT_VLD_14"},
	{true,	"Q_CREDIT_VLD_15"},
	{true,	"Q_CREDIT_VLD_16"},
	{true,	"Q_CREDIT_VLD_17"},
	{true,	"Q_CREDIT_VLD_18"},
	{true,	"Q_CREDIT_VLD_19"},

	{true,	"Q_CREDIT_VLD_20"},
	{true,	"Q_CREDIT_VLD_21"},
	{true,	"Q_CREDIT_VLD_22"},
	{true,	"Q_CREDIT_VLD_23"},
	{true,	"Q_CREDIT_VLD_24"},
	{true,	"Q_CREDIT_VLD_25"},

	{true,	"Q_CREDIT_VLD_26"},
	{true,	"Q_CREDIT_VLD_27"},
	{true,	"Q_CREDIT_VLD_28"},
	{true,	"Q_CREDIT_VLD_29"},
	{true,	"Q_CREDIT_VLD_30"},
	{true,	"Q_CREDIT_VLD_31"},

	{true,	"GRO_BD_SERR_CNT"},
	{true,	"GRO_CONTEXT_SERR_CNT"},
	{true,	"RX_STASH_CFG_SERR_CNT"},
	{true,	"AXI_RD_FBD_SERR_CNT"},
	{true,	"GRO_BD_MERR_CNT"},
	{true,	"GRO_CONTEXT_MERR_CNT"},

	{true,	"RX_STASH_CFG_MERR_CNT"},
	{true,	"AXI_RD_FBD_MERR_CNT"},
	{false, "Reserved"},
	{false, "Reserved"},
	{false, "Reserved"},
	{false, "Reserved"},
};

static const struct hclge_dbg_dfx_message hclge_dbg_tqp_reg[] = {
	{true, "q_num"},
	{true, "RCB_CFG_RX_RING_TAIL"},
	{true, "RCB_CFG_RX_RING_HEAD"},
	{true, "RCB_CFG_RX_RING_FBDNUM"},
	{true, "RCB_CFG_RX_RING_OFFSET"},
	{true, "RCB_CFG_RX_RING_FBDOFFSET"},

	{true, "RCB_CFG_RX_RING_PKTNUM_RECORD"},
	{true, "RCB_CFG_TX_RING_TAIL"},
	{true, "RCB_CFG_TX_RING_HEAD"},
	{true, "RCB_CFG_TX_RING_FBDNUM"},
	{true, "RCB_CFG_TX_RING_OFFSET"},
	{true, "RCB_CFG_TX_RING_EBDNUM"},
};

static const struct hclge_dbg_reg_type_info hclge_dbg_reg_info[] = {
	{ .cmd = HNAE3_DBG_CMD_REG_BIOS_COMMON,
	  .dfx_msg = &hclge_dbg_bios_common_reg[0],
	  .reg_msg = { .msg_num = ARRAY_SIZE(hclge_dbg_bios_common_reg),
		       .offset = HCLGE_DBG_DFX_BIOS_OFFSET,
		       .cmd = HCLGE_OPC_DFX_BIOS_COMMON_REG } },
	{ .cmd = HNAE3_DBG_CMD_REG_SSU,
	  .dfx_msg = &hclge_dbg_ssu_reg_0[0],
	  .reg_msg = { .msg_num = ARRAY_SIZE(hclge_dbg_ssu_reg_0),
		       .offset = HCLGE_DBG_DFX_SSU_0_OFFSET,
		       .cmd = HCLGE_OPC_DFX_SSU_REG_0 } },
	{ .cmd = HNAE3_DBG_CMD_REG_SSU,
	  .dfx_msg = &hclge_dbg_ssu_reg_1[0],
	  .reg_msg = { .msg_num = ARRAY_SIZE(hclge_dbg_ssu_reg_1),
		       .offset = HCLGE_DBG_DFX_SSU_1_OFFSET,
		       .cmd = HCLGE_OPC_DFX_SSU_REG_1 } },
	{ .cmd = HNAE3_DBG_CMD_REG_SSU,
	  .dfx_msg = &hclge_dbg_ssu_reg_2[0],
	  .reg_msg = { .msg_num = ARRAY_SIZE(hclge_dbg_ssu_reg_2),
		       .offset = HCLGE_DBG_DFX_SSU_2_OFFSET,
		       .cmd = HCLGE_OPC_DFX_SSU_REG_2 } },
	{ .cmd = HNAE3_DBG_CMD_REG_IGU_EGU,
	  .dfx_msg = &hclge_dbg_igu_egu_reg[0],
	  .reg_msg = { .msg_num = ARRAY_SIZE(hclge_dbg_igu_egu_reg),
		       .offset = HCLGE_DBG_DFX_IGU_OFFSET,
		       .cmd = HCLGE_OPC_DFX_IGU_EGU_REG } },
	{ .cmd = HNAE3_DBG_CMD_REG_RPU,
	  .dfx_msg = &hclge_dbg_rpu_reg_0[0],
	  .reg_msg = { .msg_num = ARRAY_SIZE(hclge_dbg_rpu_reg_0),
		       .offset = HCLGE_DBG_DFX_RPU_0_OFFSET,
		       .cmd = HCLGE_OPC_DFX_RPU_REG_0 } },
	{ .cmd = HNAE3_DBG_CMD_REG_RPU,
	  .dfx_msg = &hclge_dbg_rpu_reg_1[0],
	  .reg_msg = { .msg_num = ARRAY_SIZE(hclge_dbg_rpu_reg_1),
		       .offset = HCLGE_DBG_DFX_RPU_1_OFFSET,
		       .cmd = HCLGE_OPC_DFX_RPU_REG_1 } },
	{ .cmd = HNAE3_DBG_CMD_REG_NCSI,
	  .dfx_msg = &hclge_dbg_ncsi_reg[0],
	  .reg_msg = { .msg_num = ARRAY_SIZE(hclge_dbg_ncsi_reg),
		       .offset = HCLGE_DBG_DFX_NCSI_OFFSET,
		       .cmd = HCLGE_OPC_DFX_NCSI_REG } },
	{ .cmd = HNAE3_DBG_CMD_REG_RTC,
	  .dfx_msg = &hclge_dbg_rtc_reg[0],
	  .reg_msg = { .msg_num = ARRAY_SIZE(hclge_dbg_rtc_reg),
		       .offset = HCLGE_DBG_DFX_RTC_OFFSET,
		       .cmd = HCLGE_OPC_DFX_RTC_REG } },
	{ .cmd = HNAE3_DBG_CMD_REG_PPP,
	  .dfx_msg = &hclge_dbg_ppp_reg[0],
	  .reg_msg = { .msg_num = ARRAY_SIZE(hclge_dbg_ppp_reg),
		       .offset = HCLGE_DBG_DFX_PPP_OFFSET,
		       .cmd = HCLGE_OPC_DFX_PPP_REG } },
	{ .cmd = HNAE3_DBG_CMD_REG_RCB,
	  .dfx_msg = &hclge_dbg_rcb_reg[0],
	  .reg_msg = { .msg_num = ARRAY_SIZE(hclge_dbg_rcb_reg),
		       .offset = HCLGE_DBG_DFX_RCB_OFFSET,
		       .cmd = HCLGE_OPC_DFX_RCB_REG } },
	{ .cmd = HNAE3_DBG_CMD_REG_TQP,
	  .dfx_msg = &hclge_dbg_tqp_reg[0],
	  .reg_msg = { .msg_num = ARRAY_SIZE(hclge_dbg_tqp_reg),
		       .offset = HCLGE_DBG_DFX_TQP_OFFSET,
		       .cmd = HCLGE_OPC_DFX_TQP_REG } },
};

static char *hclge_dbg_get_func_id_str(char *buf, u8 id)
{
	if (id)
		sprintf(buf, "vf%u", id - 1U);
	else
		sprintf(buf, "pf");

	return buf;
}

static int hclge_dbg_get_dfx_bd_num(struct hclge_dev *hdev, int offset,
				    u32 *bd_num)
{
	struct hclge_desc desc[HCLGE_GET_DFX_REG_TYPE_CNT];
	int entries_per_desc;
	int index;
	int ret;

	ret = hclge_query_bd_num_cmd_send(hdev, desc);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to get dfx bd_num, offset = %d, ret = %d\n",
			offset, ret);
		return ret;
	}

	entries_per_desc = ARRAY_SIZE(desc[0].data);
	index = offset % entries_per_desc;

	*bd_num = le32_to_cpu(desc[offset / entries_per_desc].data[index]);
	if (!(*bd_num)) {
		dev_err(&hdev->pdev->dev, "The value of dfx bd_num is 0!\n");
		return -EINVAL;
	}

	return 0;
}

int hclge_dbg_cmd_send(struct hclge_dev *hdev, struct hclge_desc *desc_src,
		       int index, int bd_num, enum hclge_opcode_type cmd)
{
	struct hclge_desc *desc = desc_src;
	int ret, i;

	hclge_cmd_setup_basic_desc(desc, cmd, true);
	desc->data[0] = cpu_to_le32(index);

	for (i = 1; i < bd_num; i++) {
		desc->flag |= cpu_to_le16(HCLGE_COMM_CMD_FLAG_NEXT);
		desc++;
		hclge_cmd_setup_basic_desc(desc, cmd, true);
	}

	ret = hclge_cmd_send(&hdev->hw, desc_src, bd_num);
	if (ret)
		dev_err(&hdev->pdev->dev,
			"cmd(0x%x) send fail, ret = %d\n", cmd, ret);
	return ret;
}

static int
hclge_dbg_dump_reg_tqp(struct hclge_dev *hdev,
		       const struct hclge_dbg_reg_type_info *reg_info,
		       struct seq_file *s)
{
	const struct hclge_dbg_dfx_message *dfx_message = reg_info->dfx_msg;
	const struct hclge_dbg_reg_common_msg *reg_msg = &reg_info->reg_msg;
	u32 index, entry, i, cnt, min_num;
	struct hclge_desc *desc_src;
	struct hclge_desc *desc;
	int bd_num, ret;

	ret = hclge_dbg_get_dfx_bd_num(hdev, reg_msg->offset, &bd_num);
	if (ret)
		return ret;

	desc_src = kcalloc(bd_num, sizeof(struct hclge_desc), GFP_KERNEL);
	if (!desc_src)
		return -ENOMEM;

	min_num = min_t(int, bd_num * HCLGE_DESC_DATA_LEN, reg_msg->msg_num);

	for (i = 0, cnt = 0; i < min_num; i++, dfx_message++)
		seq_printf(s, "item%u = %s\n", cnt++, dfx_message->message);

	for (i = 0; i < cnt; i++)
		seq_printf(s, "item%u\t", i);

	seq_puts(s, "\n");

	for (index = 0; index < hdev->vport[0].alloc_tqps; index++) {
		dfx_message = reg_info->dfx_msg;
		desc = desc_src;
		ret = hclge_dbg_cmd_send(hdev, desc, index, bd_num,
					 reg_msg->cmd);
		if (ret)
			break;

		for (i = 0; i < min_num; i++, dfx_message++) {
			entry = i % HCLGE_DESC_DATA_LEN;
			if (i > 0 && !entry)
				desc++;

			seq_printf(s, "%#x\t", le32_to_cpu(desc->data[entry]));
		}
		seq_puts(s, "\n");
	}

	kfree(desc_src);
	return ret;
}

static int
hclge_dbg_dump_reg_common(struct hclge_dev *hdev,
			  const struct hclge_dbg_reg_type_info *reg_info,
			  struct seq_file *s)
{
	const struct hclge_dbg_reg_common_msg *reg_msg = &reg_info->reg_msg;
	const struct hclge_dbg_dfx_message *dfx_message = reg_info->dfx_msg;
	struct hclge_desc *desc_src;
	int bd_num, min_num, ret, i;
	struct hclge_desc *desc;
	u32 entry;

	ret = hclge_dbg_get_dfx_bd_num(hdev, reg_msg->offset, &bd_num);
	if (ret)
		return ret;

	desc_src = kcalloc(bd_num, sizeof(struct hclge_desc), GFP_KERNEL);
	if (!desc_src)
		return -ENOMEM;

	desc = desc_src;

	ret = hclge_dbg_cmd_send(hdev, desc, 0, bd_num, reg_msg->cmd);
	if (ret) {
		kfree(desc);
		return ret;
	}

	min_num = min_t(int, bd_num * HCLGE_DESC_DATA_LEN, reg_msg->msg_num);

	for (i = 0; i < min_num; i++, dfx_message++) {
		entry = i % HCLGE_DESC_DATA_LEN;
		if (i > 0 && !entry)
			desc++;
		if (!dfx_message->flag)
			continue;

		seq_printf(s, "%s: %#x\n", dfx_message->message,
			   le32_to_cpu(desc->data[entry]));
	}

	kfree(desc_src);
	return 0;
}

static const struct hclge_dbg_status_dfx_info hclge_dbg_mac_en_status[] = {
	{HCLGE_MAC_TX_EN_B,  "mac_trans_en"},
	{HCLGE_MAC_RX_EN_B,  "mac_rcv_en"},
	{HCLGE_MAC_PAD_TX_B, "pad_trans_en"},
	{HCLGE_MAC_PAD_RX_B, "pad_rcv_en"},
	{HCLGE_MAC_1588_TX_B, "1588_trans_en"},
	{HCLGE_MAC_1588_RX_B, "1588_rcv_en"},
	{HCLGE_MAC_APP_LP_B,  "mac_app_loop_en"},
	{HCLGE_MAC_LINE_LP_B, "mac_line_loop_en"},
	{HCLGE_MAC_FCS_TX_B,  "mac_fcs_tx_en"},
	{HCLGE_MAC_RX_OVERSIZE_TRUNCATE_B, "mac_rx_oversize_truncate_en"},
	{HCLGE_MAC_RX_FCS_STRIP_B, "mac_rx_fcs_strip_en"},
	{HCLGE_MAC_RX_FCS_B, "mac_rx_fcs_en"},
	{HCLGE_MAC_TX_UNDER_MIN_ERR_B, "mac_tx_under_min_err_en"},
	{HCLGE_MAC_TX_OVERSIZE_TRUNCATE_B, "mac_tx_oversize_truncate_en"}
};

static int hclge_dbg_dump_mac_enable_status(struct hclge_dev *hdev,
					    struct seq_file *s)
{
	struct hclge_config_mac_mode_cmd *req;
	struct hclge_desc desc;
	u32 loop_en, i, offset;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_CONFIG_MAC_MODE, true);

	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump mac enable status, ret = %d\n", ret);
		return ret;
	}

	req = (struct hclge_config_mac_mode_cmd *)desc.data;
	loop_en = le32_to_cpu(req->txrx_pad_fcs_loop_en);

	for (i = 0; i < ARRAY_SIZE(hclge_dbg_mac_en_status); i++) {
		offset = hclge_dbg_mac_en_status[i].offset;
		seq_printf(s, "%s: %#x\n", hclge_dbg_mac_en_status[i].message,
			   hnae3_get_bit(loop_en, offset));
	}

	return 0;
}

static int hclge_dbg_dump_mac_frame_size(struct hclge_dev *hdev,
					 struct seq_file *s)
{
	struct hclge_config_max_frm_size_cmd *req;
	struct hclge_desc desc;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_CONFIG_MAX_FRM_SIZE, true);

	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump mac frame size, ret = %d\n", ret);
		return ret;
	}

	req = (struct hclge_config_max_frm_size_cmd *)desc.data;

	seq_printf(s, "max_frame_size: %u\n", le16_to_cpu(req->max_frm_size));
	seq_printf(s, "min_frame_size: %u\n", req->min_frm_size);

	return 0;
}

static int hclge_dbg_dump_mac_speed_duplex(struct hclge_dev *hdev,
					   struct seq_file *s)
{
#define HCLGE_MAC_SPEED_SHIFT	0
#define HCLGE_MAC_SPEED_MASK	GENMASK(5, 0)
#define HCLGE_MAC_DUPLEX_SHIFT	7

	struct hclge_config_mac_speed_dup_cmd *req;
	struct hclge_desc desc;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_CONFIG_SPEED_DUP, true);

	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump mac speed duplex, ret = %d\n", ret);
		return ret;
	}

	req = (struct hclge_config_mac_speed_dup_cmd *)desc.data;

	seq_printf(s, "speed: %#lx\n",
		   hnae3_get_field(req->speed_dup, HCLGE_MAC_SPEED_MASK,
				   HCLGE_MAC_SPEED_SHIFT));
	seq_printf(s, "duplex: %#x\n",
		   hnae3_get_bit(req->speed_dup, HCLGE_MAC_DUPLEX_SHIFT));
	return 0;
}

static int hclge_dbg_dump_mac(struct seq_file *s, void *data)
{
	struct hclge_dev *hdev = hclge_seq_file_to_hdev(s);
	int ret;

	ret = hclge_dbg_dump_mac_enable_status(hdev, s);
	if (ret)
		return ret;

	ret = hclge_dbg_dump_mac_frame_size(hdev, s);
	if (ret)
		return ret;

	return hclge_dbg_dump_mac_speed_duplex(hdev, s);
}

static int hclge_dbg_dump_dcb_qset(struct hclge_dev *hdev, struct seq_file *s)
{
	struct hclge_dbg_bitmap_cmd req;
	struct hclge_desc desc;
	u16 qset_id, qset_num;
	int ret;

	ret = hclge_tm_get_qset_num(hdev, &qset_num);
	if (ret)
		return ret;

	seq_puts(s, "qset_id  roce_qset_mask  nic_qset_mask  ");
	seq_puts(s, "qset_shaping_pass  qset_bp_status\n");
	for (qset_id = 0; qset_id < qset_num; qset_id++) {
		ret = hclge_dbg_cmd_send(hdev, &desc, qset_id, 1,
					 HCLGE_OPC_QSET_DFX_STS);
		if (ret)
			return ret;

		req.bitmap = (u8)le32_to_cpu(desc.data[1]);

		seq_printf(s, "%04u     %#-16x%#-15x%#-19x%#-x\n",
			   qset_id, req.bit0, req.bit1, req.bit2, req.bit3);
	}

	return 0;
}

static int hclge_dbg_dump_dcb_pri(struct hclge_dev *hdev, struct seq_file *s)
{
	struct hclge_dbg_bitmap_cmd req;
	struct hclge_desc desc;
	u8 pri_id, pri_num;
	int ret;

	ret = hclge_tm_get_pri_num(hdev, &pri_num);
	if (ret)
		return ret;

	seq_puts(s, "pri_id  pri_mask  pri_cshaping_pass  pri_pshaping_pass\n");
	for (pri_id = 0; pri_id < pri_num; pri_id++) {
		ret = hclge_dbg_cmd_send(hdev, &desc, pri_id, 1,
					 HCLGE_OPC_PRI_DFX_STS);
		if (ret)
			return ret;

		req.bitmap = (u8)le32_to_cpu(desc.data[1]);

		seq_printf(s, "%03u     %#-10x%#-19x%#-x\n",
			   pri_id, req.bit0, req.bit1, req.bit2);
	}

	return 0;
}

static int hclge_dbg_dump_dcb_pg(struct hclge_dev *hdev, struct seq_file *s)
{
	struct hclge_dbg_bitmap_cmd req;
	struct hclge_desc desc;
	u8 pg_id;
	int ret;

	seq_puts(s, "pg_id  pg_mask  pg_cshaping_pass  pg_pshaping_pass\n");
	for (pg_id = 0; pg_id < hdev->tm_info.num_pg; pg_id++) {
		ret = hclge_dbg_cmd_send(hdev, &desc, pg_id, 1,
					 HCLGE_OPC_PG_DFX_STS);
		if (ret)
			return ret;

		req.bitmap = (u8)le32_to_cpu(desc.data[1]);

		seq_printf(s, "%03u    %#-9x%#-18x%#-x\n",
			   pg_id, req.bit0, req.bit1, req.bit2);
	}

	return 0;
}

static int hclge_dbg_dump_dcb_queue(struct hclge_dev *hdev, struct seq_file *s)
{
	struct hclge_desc desc;
	u16 nq_id;
	int ret;

	seq_puts(s, "nq_id  sch_nic_queue_cnt  sch_roce_queue_cnt\n");
	for (nq_id = 0; nq_id < hdev->num_tqps; nq_id++) {
		ret = hclge_dbg_cmd_send(hdev, &desc, nq_id, 1,
					 HCLGE_OPC_SCH_NQ_CNT);
		if (ret)
			return ret;

		seq_printf(s, "%04u   %#-19x",
			   nq_id, le32_to_cpu(desc.data[1]));

		ret = hclge_dbg_cmd_send(hdev, &desc, nq_id, 1,
					 HCLGE_OPC_SCH_RQ_CNT);
		if (ret)
			return ret;

		seq_printf(s, "%#-x\n", le32_to_cpu(desc.data[1]));
	}

	return 0;
}

static int hclge_dbg_dump_dcb_port(struct hclge_dev *hdev, struct seq_file *s)
{
	struct hclge_dbg_bitmap_cmd req;
	struct hclge_desc desc;
	u8 port_id = 0;
	int ret;

	ret = hclge_dbg_cmd_send(hdev, &desc, port_id, 1,
				 HCLGE_OPC_PORT_DFX_STS);
	if (ret)
		return ret;

	req.bitmap = (u8)le32_to_cpu(desc.data[1]);

	seq_printf(s, "port_mask: %#x\n", req.bit0);
	seq_printf(s, "port_shaping_pass: %#x\n", req.bit1);

	return 0;
}

static int hclge_dbg_dump_dcb_tm(struct hclge_dev *hdev, struct seq_file *s)
{
	struct hclge_desc desc[2];
	u8 port_id = 0;
	int ret;

	ret = hclge_dbg_cmd_send(hdev, desc, port_id, 1,
				 HCLGE_OPC_TM_INTERNAL_CNT);
	if (ret)
		return ret;

	seq_printf(s, "SCH_NIC_NUM: %#x\n", le32_to_cpu(desc[0].data[1]));
	seq_printf(s, "SCH_ROCE_NUM: %#x\n", le32_to_cpu(desc[0].data[2]));

	ret = hclge_dbg_cmd_send(hdev, desc, port_id, 2,
				 HCLGE_OPC_TM_INTERNAL_STS);
	if (ret)
		return ret;

	seq_printf(s, "pri_bp: %#x\n", le32_to_cpu(desc[0].data[1]));
	seq_printf(s, "fifo_dfx_info: %#x\n", le32_to_cpu(desc[0].data[2]));
	seq_printf(s, "sch_roce_fifo_afull_gap: %#x\n",
		   le32_to_cpu(desc[0].data[3]));
	seq_printf(s, "tx_private_waterline: %#x\n",
		   le32_to_cpu(desc[0].data[4]));
	seq_printf(s, "tm_bypass_en: %#x\n", le32_to_cpu(desc[0].data[5]));
	seq_printf(s, "SSU_TM_BYPASS_EN: %#x\n", le32_to_cpu(desc[1].data[0]));
	seq_printf(s, "SSU_RESERVE_CFG: %#x\n", le32_to_cpu(desc[1].data[1]));

	if (hdev->hw.mac.media_type == HNAE3_MEDIA_TYPE_COPPER)
		return 0;

	ret = hclge_dbg_cmd_send(hdev, desc, port_id, 1,
				 HCLGE_OPC_TM_INTERNAL_STS_1);
	if (ret)
		return ret;

	seq_printf(s, "TC_MAP_SEL: %#x\n", le32_to_cpu(desc[0].data[1]));
	seq_printf(s, "IGU_PFC_PRI_EN: %#x\n", le32_to_cpu(desc[0].data[2]));
	seq_printf(s, "MAC_PFC_PRI_EN: %#x\n", le32_to_cpu(desc[0].data[3]));
	seq_printf(s, "IGU_PRI_MAP_TC_CFG: %#x\n",
		   le32_to_cpu(desc[0].data[4]));
	seq_printf(s, "IGU_TX_PRI_MAP_TC_CFG: %#x\n",
		   le32_to_cpu(desc[0].data[5]));

	return 0;
}

static int hclge_dbg_dump_dcb(struct seq_file *s, void *data)
{
	struct hclge_dev *hdev = hclge_seq_file_to_hdev(s);
	int ret;

	ret = hclge_dbg_dump_dcb_qset(hdev, s);
	if (ret)
		return ret;

	ret = hclge_dbg_dump_dcb_pri(hdev, s);
	if (ret)
		return ret;

	ret = hclge_dbg_dump_dcb_pg(hdev, s);
	if (ret)
		return ret;

	ret = hclge_dbg_dump_dcb_queue(hdev, s);
	if (ret)
		return ret;

	ret = hclge_dbg_dump_dcb_port(hdev, s);
	if (ret)
		return ret;

	return hclge_dbg_dump_dcb_tm(hdev, s);
}

static int hclge_dbg_dump_reg_cmd(enum hnae3_dbg_cmd cmd, struct seq_file *s)
{
	struct hclge_dev *hdev = hclge_seq_file_to_hdev(s);
	const struct hclge_dbg_reg_type_info *reg_info;
	int ret = 0;
	u32 i;

	for (i = 0; i < ARRAY_SIZE(hclge_dbg_reg_info); i++) {
		reg_info = &hclge_dbg_reg_info[i];
		if (cmd == reg_info->cmd) {
			if (cmd == HNAE3_DBG_CMD_REG_TQP)
				return hclge_dbg_dump_reg_tqp(hdev,
							      reg_info, s);

			ret = hclge_dbg_dump_reg_common(hdev, reg_info, s);
			if (ret)
				break;
		}
	}

	return ret;
}

static int hclge_dbg_dump_bios_reg_cmd(struct seq_file *s, void *data)
{
	return hclge_dbg_dump_reg_cmd(HNAE3_DBG_CMD_REG_BIOS_COMMON, s);
}

static int hclge_dbg_dump_ssu_reg_cmd(struct seq_file *s, void *data)
{
	return hclge_dbg_dump_reg_cmd(HNAE3_DBG_CMD_REG_SSU, s);
}

static int hclge_dbg_dump_igu_egu_reg_cmd(struct seq_file *s, void *data)
{
	return hclge_dbg_dump_reg_cmd(HNAE3_DBG_CMD_REG_IGU_EGU, s);
}

static int hclge_dbg_dump_rpu_reg_cmd(struct seq_file *s, void *data)
{
	return hclge_dbg_dump_reg_cmd(HNAE3_DBG_CMD_REG_RPU, s);
}

static int hclge_dbg_dump_ncsi_reg_cmd(struct seq_file *s, void *data)
{
	return hclge_dbg_dump_reg_cmd(HNAE3_DBG_CMD_REG_NCSI, s);
}

static int hclge_dbg_dump_rtc_reg_cmd(struct seq_file *s, void *data)
{
	return hclge_dbg_dump_reg_cmd(HNAE3_DBG_CMD_REG_RTC, s);
}

static int hclge_dbg_dump_ppp_reg_cmd(struct seq_file *s, void *data)
{
	return hclge_dbg_dump_reg_cmd(HNAE3_DBG_CMD_REG_PPP, s);
}

static int hclge_dbg_dump_rcb_reg_cmd(struct seq_file *s, void *data)
{
	return hclge_dbg_dump_reg_cmd(HNAE3_DBG_CMD_REG_RCB, s);
}

static int hclge_dbg_dump_tqp_reg_cmd(struct seq_file *s, void *data)
{
	return hclge_dbg_dump_reg_cmd(HNAE3_DBG_CMD_REG_TQP, s);
}

static int hclge_dbg_dump_tc(struct seq_file *s, void *data)
{
	struct hclge_dev *hdev = hclge_seq_file_to_hdev(s);
	struct hclge_ets_tc_weight_cmd *ets_weight;
	const char *sch_mode_str;
	struct hclge_desc desc;
	int ret;
	u8 i;

	if (!hnae3_dev_dcb_supported(hdev)) {
		dev_err(&hdev->pdev->dev,
			"Only DCB-supported dev supports tc\n");
		return -EOPNOTSUPP;
	}

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_ETS_TC_WEIGHT, true);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev, "failed to get tc weight, ret = %d\n",
			ret);
		return ret;
	}

	ets_weight = (struct hclge_ets_tc_weight_cmd *)desc.data;

	seq_printf(s, "enabled tc number: %u\n", hdev->tm_info.num_tc);
	seq_printf(s, "weight_offset: %u\n", ets_weight->weight_offset);

	seq_puts(s, "TC    MODE  WEIGHT\n");
	for (i = 0; i < HNAE3_MAX_TC; i++) {
		sch_mode_str = ets_weight->tc_weight[i] ? "dwrr" : "sp";
		seq_printf(s, "%u     %4s    %3u\n", i, sch_mode_str,
			   ets_weight->tc_weight[i]);
	}

	return 0;
}

static void hclge_dbg_fill_shaper_content(struct seq_file *s,
					  struct hclge_tm_shaper_para *para)
{
	seq_printf(s, "%-8u%-8u%-8u%-8u%-8u%-8u%-14u", para->ir_b, para->ir_u,
		   para->ir_s, para->bs_b, para->bs_s, para->flag, para->rate);
}

static int hclge_dbg_dump_tm_pg(struct seq_file *s, void *data)
{
	struct hclge_tm_shaper_para c_shaper_para, p_shaper_para;
	struct hclge_dev *hdev = hclge_seq_file_to_hdev(s);
	u8 pg_id, sch_mode, weight, pri_bit_map;
	const char *sch_mode_str;
	int ret;

	seq_puts(s, "ID  PRI_MAP  MODE  DWRR  C_IR_B  C_IR_U  C_IR_S  C_BS_B  ");
	seq_puts(s, "C_BS_S  C_FLAG  C_RATE(Mbps)  P_IR_B  P_IR_U  P_IR_S  ");
	seq_puts(s, "P_BS_B  P_BS_S  P_FLAG  P_RATE(Mbps)\n");

	for (pg_id = 0; pg_id < hdev->tm_info.num_pg; pg_id++) {
		ret = hclge_tm_get_pg_to_pri_map(hdev, pg_id, &pri_bit_map);
		if (ret)
			return ret;

		ret = hclge_tm_get_pg_sch_mode(hdev, pg_id, &sch_mode);
		if (ret)
			return ret;

		ret = hclge_tm_get_pg_weight(hdev, pg_id, &weight);
		if (ret)
			return ret;

		ret = hclge_tm_get_pg_shaper(hdev, pg_id,
					     HCLGE_OPC_TM_PG_C_SHAPPING,
					     &c_shaper_para);
		if (ret)
			return ret;

		ret = hclge_tm_get_pg_shaper(hdev, pg_id,
					     HCLGE_OPC_TM_PG_P_SHAPPING,
					     &p_shaper_para);
		if (ret)
			return ret;

		sch_mode_str = sch_mode & HCLGE_TM_TX_SCHD_DWRR_MSK ? "dwrr" :
				       "sp";

		seq_printf(s, "%02u  0x%-7x%-6s%-6u", pg_id, pri_bit_map,
			   sch_mode_str, weight);
		hclge_dbg_fill_shaper_content(s, &c_shaper_para);
		hclge_dbg_fill_shaper_content(s, &p_shaper_para);
		seq_puts(s, "\n");
	}

	return 0;
}

static int hclge_dbg_dump_tm_port(struct seq_file *s, void *data)
{
	struct hclge_dev *hdev = hclge_seq_file_to_hdev(s);
	struct hclge_tm_shaper_para shaper_para;
	int ret;

	ret = hclge_tm_get_port_shaper(hdev, &shaper_para);
	if (ret)
		return ret;

	seq_puts(s, "IR_B  IR_U  IR_S  BS_B  BS_S  FLAG  RATE(Mbps)\n");
	seq_printf(s, "%3u   %3u   %3u   %3u   %3u     %1u   %6u\n",
		   shaper_para.ir_b, shaper_para.ir_u, shaper_para.ir_s,
		   shaper_para.bs_b, shaper_para.bs_s, shaper_para.flag,
		   shaper_para.rate);

	return 0;
}

static int hclge_dbg_dump_tm_bp_qset_map(struct hclge_dev *hdev, u8 tc_id,
					 struct seq_file *s)
{
	u32 qset_mapping[HCLGE_BP_EXT_GRP_NUM];
	struct hclge_bp_to_qs_map_cmd *map;
	struct hclge_desc desc;
	u8 group_id;
	u8 grp_num;
	u16 i = 0;
	int ret;

	grp_num = hdev->num_tqps <= HCLGE_TQP_MAX_SIZE_DEV_V2 ?
		  HCLGE_BP_GRP_NUM : HCLGE_BP_EXT_GRP_NUM;
	map = (struct hclge_bp_to_qs_map_cmd *)desc.data;
	for (group_id = 0; group_id < grp_num; group_id++) {
		hclge_cmd_setup_basic_desc(&desc,
					   HCLGE_OPC_TM_BP_TO_QSET_MAPPING,
					   true);
		map->tc_id = tc_id;
		map->qs_group_id = group_id;
		ret = hclge_cmd_send(&hdev->hw, &desc, 1);
		if (ret) {
			dev_err(&hdev->pdev->dev,
				"failed to get bp to qset map, ret = %d\n",
				ret);
			return ret;
		}

		qset_mapping[group_id] = le32_to_cpu(map->qs_bit_map);
	}

	seq_puts(s, "INDEX | TM BP QSET MAPPING:\n");
	for (group_id = 0; group_id < grp_num / 8; group_id++) {
		seq_printf(s,
			   "%04d  | %08x:%08x:%08x:%08x:%08x:%08x:%08x:%08x\n",
			   group_id * 256, qset_mapping[i + 7],
			   qset_mapping[i + 6], qset_mapping[i + 5],
			   qset_mapping[i + 4], qset_mapping[i + 3],
			   qset_mapping[i + 2], qset_mapping[i + 1],
			   qset_mapping[i]);
		i += 8;
	}

	return 0;
}

static int hclge_dbg_dump_tm_map(struct seq_file *s, void *data)
{
	struct hclge_dev *hdev = hclge_seq_file_to_hdev(s);
	u16 queue_id;
	u16 qset_id;
	u8 link_vld;
	u8 pri_id;
	u8 tc_id;
	int ret;

	for (queue_id = 0; queue_id < hdev->num_tqps; queue_id++) {
		ret = hclge_tm_get_q_to_qs_map(hdev, queue_id, &qset_id);
		if (ret)
			return ret;

		ret = hclge_tm_get_qset_map_pri(hdev, qset_id, &pri_id,
						&link_vld);
		if (ret)
			return ret;

		ret = hclge_tm_get_q_to_tc(hdev, queue_id, &tc_id);
		if (ret)
			return ret;

		seq_puts(s, "QUEUE_ID   QSET_ID   PRI_ID   TC_ID\n");
		seq_printf(s, "%04u        %4u       %3u      %2u\n",
			   queue_id, qset_id, pri_id, tc_id);

		if (!hnae3_dev_dcb_supported(hdev))
			continue;

		ret = hclge_dbg_dump_tm_bp_qset_map(hdev, tc_id, s);
		if (ret < 0)
			return ret;

		seq_puts(s, "\n");
	}

	return 0;
}

static int hclge_dbg_dump_tm_nodes(struct seq_file *s, void *data)
{
	struct hclge_dev *hdev = hclge_seq_file_to_hdev(s);
	struct hclge_tm_nodes_cmd *nodes;
	struct hclge_desc desc;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_TM_NODES, true);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump tm nodes, ret = %d\n", ret);
		return ret;
	}

	nodes = (struct hclge_tm_nodes_cmd *)desc.data;

	seq_puts(s, "       BASE_ID  MAX_NUM\n");
	seq_printf(s, "PG      %4u      %4u\n", nodes->pg_base_id,
		   nodes->pg_num);
	seq_printf(s, "PRI     %4u      %4u\n", nodes->pri_base_id,
		   nodes->pri_num);
	seq_printf(s, "QSET    %4u      %4u\n",
		   le16_to_cpu(nodes->qset_base_id),
		   le16_to_cpu(nodes->qset_num));
	seq_printf(s, "QUEUE   %4u      %4u\n",
		   le16_to_cpu(nodes->queue_base_id),
		   le16_to_cpu(nodes->queue_num));

	return 0;
}

static int hclge_dbg_dump_tm_pri(struct seq_file *s, void *data)
{
	struct hclge_tm_shaper_para c_shaper_para, p_shaper_para;
	struct hclge_dev *hdev = hclge_seq_file_to_hdev(s);
	u8 pri_num, sch_mode, weight, i;
	const char *sch_mode_str;
	int ret;

	ret = hclge_tm_get_pri_num(hdev, &pri_num);
	if (ret)
		return ret;

	seq_puts(s, "ID  MODE  DWRR  C_IR_B  C_IR_U  C_IR_S  C_BS_B  ");
	seq_puts(s, "C_BS_S  C_FLAG  C_RATE(Mbps)  P_IR_B  P_IR_U  P_IR_S  ");
	seq_puts(s, "P_BS_B  P_BS_S  P_FLAG  P_RATE(Mbps)\n");

	for (i = 0; i < pri_num; i++) {
		ret = hclge_tm_get_pri_sch_mode(hdev, i, &sch_mode);
		if (ret)
			goto out;

		ret = hclge_tm_get_pri_weight(hdev, i, &weight);
		if (ret)
			goto out;

		ret = hclge_tm_get_pri_shaper(hdev, i,
					      HCLGE_OPC_TM_PRI_C_SHAPPING,
					      &c_shaper_para);
		if (ret)
			goto out;

		ret = hclge_tm_get_pri_shaper(hdev, i,
					      HCLGE_OPC_TM_PRI_P_SHAPPING,
					      &p_shaper_para);
		if (ret)
			goto out;

		sch_mode_str = sch_mode & HCLGE_TM_TX_SCHD_DWRR_MSK ? "dwrr" :
			       "sp";

		seq_printf(s, "%04u  %-6s%-6u", i, sch_mode_str, weight);
		hclge_dbg_fill_shaper_content(s, &c_shaper_para);
		hclge_dbg_fill_shaper_content(s, &p_shaper_para);
		seq_puts(s, "\n");
	}

out:
	return ret;
}

static int hclge_dbg_dump_tm_qset(struct seq_file *s, void *data)
{
	struct hclge_dev *hdev = hclge_seq_file_to_hdev(s);
	u8 priority, link_vld, sch_mode, weight;
	struct hclge_tm_shaper_para shaper_para;
	const char *sch_mode_str;
	u16 qset_num, i;
	int ret;

	ret = hclge_tm_get_qset_num(hdev, &qset_num);
	if (ret)
		return ret;

	seq_puts(s, "ID    MAP_PRI  LINK_VLD  MODE  DWRR  IR_B  IR_U  IR_S  ");
	seq_puts(s, "BS_B  BS_S  FLAG  RATE(Mbps)\n");

	for (i = 0; i < qset_num; i++) {
		ret = hclge_tm_get_qset_map_pri(hdev, i, &priority, &link_vld);
		if (ret)
			return ret;

		ret = hclge_tm_get_qset_sch_mode(hdev, i, &sch_mode);
		if (ret)
			return ret;

		ret = hclge_tm_get_qset_weight(hdev, i, &weight);
		if (ret)
			return ret;

		ret = hclge_tm_get_qset_shaper(hdev, i, &shaper_para);
		if (ret)
			return ret;

		sch_mode_str = sch_mode & HCLGE_TM_TX_SCHD_DWRR_MSK ? "dwrr" :
			       "sp";

		seq_printf(s, "%04u  %-9u%-10u%-6s%-6u", i, priority, link_vld,
			   sch_mode_str, weight);
		seq_printf(s, "%-6u%-6u%-6u%-6u%-6u%-6u%-14u\n",
			   shaper_para.ir_b, shaper_para.ir_u, shaper_para.ir_s,
			   shaper_para.bs_b, shaper_para.bs_s, shaper_para.flag,
			   shaper_para.rate);
	}

	return 0;
}

static int hclge_dbg_dump_qos_pause_cfg(struct seq_file *s, void *data)
{
	struct hclge_dev *hdev = hclge_seq_file_to_hdev(s);
	struct hclge_cfg_pause_param_cmd *pause_param;
	struct hclge_desc desc;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_CFG_MAC_PARA, true);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump qos pause, ret = %d\n", ret);
		return ret;
	}

	pause_param = (struct hclge_cfg_pause_param_cmd *)desc.data;

	seq_printf(s, "pause_trans_gap: 0x%x\n", pause_param->pause_trans_gap);
	seq_printf(s, "pause_trans_time: 0x%x\n",
		   le16_to_cpu(pause_param->pause_trans_time));
	return 0;
}

#define HCLGE_DBG_TC_MASK		0x0F

static int hclge_dbg_dump_qos_pri_map(struct seq_file *s, void *data)
{
#define HCLGE_DBG_TC_BIT_WIDTH		4

	struct hclge_dev *hdev = hclge_seq_file_to_hdev(s);
	struct hclge_qos_pri_map_cmd *pri_map;
	struct hclge_desc desc;
	u8 *pri_tc;
	u8 tc, i;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_PRI_TO_TC_MAPPING, true);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump qos pri map, ret = %d\n", ret);
		return ret;
	}

	pri_map = (struct hclge_qos_pri_map_cmd *)desc.data;

	seq_printf(s, "vlan_to_pri: 0x%x\n", pri_map->vlan_pri);
	seq_puts(s, "PRI  TC\n");

	pri_tc = (u8 *)pri_map;
	for (i = 0; i < HNAE3_MAX_TC; i++) {
		tc = pri_tc[i >> 1] >> ((i & 1) * HCLGE_DBG_TC_BIT_WIDTH);
		tc &= HCLGE_DBG_TC_MASK;
		seq_printf(s, "%u     %u\n", i, tc);
	}

	return 0;
}

static int hclge_dbg_dump_qos_dscp_map(struct seq_file *s, void *data)
{
	struct hclge_dev *hdev = hclge_seq_file_to_hdev(s);
	struct hclge_desc desc[HCLGE_DSCP_MAP_TC_BD_NUM];
	struct hnae3_knic_private_info *kinfo;
	u8 *req0 = (u8 *)desc[0].data;
	u8 *req1 = (u8 *)desc[1].data;
	u8 dscp_tc[HNAE3_MAX_DSCP];
	int ret;
	u8 i, j;

	kinfo = &hdev->vport[0].nic.kinfo;

	seq_printf(s, "tc map mode: %s\n", tc_map_mode_str[kinfo->tc_map_mode]);

	if (kinfo->tc_map_mode != HNAE3_TC_MAP_MODE_DSCP)
		return 0;

	hclge_cmd_setup_basic_desc(&desc[0], HCLGE_OPC_QOS_MAP, true);
	desc[0].flag |= cpu_to_le16(HCLGE_COMM_CMD_FLAG_NEXT);
	hclge_cmd_setup_basic_desc(&desc[1], HCLGE_OPC_QOS_MAP, true);
	ret = hclge_cmd_send(&hdev->hw, desc, HCLGE_DSCP_MAP_TC_BD_NUM);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump qos dscp map, ret = %d\n", ret);
		return ret;
	}

	seq_puts(s, "\nDSCP  PRIO  TC\n");

	/* The low 32 dscp setting use bd0, high 32 dscp setting use bd1 */
	for (i = 0; i < HNAE3_MAX_DSCP / HCLGE_DSCP_MAP_TC_BD_NUM; i++) {
		j = i + HNAE3_MAX_DSCP / HCLGE_DSCP_MAP_TC_BD_NUM;
		/* Each dscp setting has 4 bits, so each byte saves two dscp
		 * setting
		 */
		dscp_tc[i] = req0[i >> 1] >> HCLGE_DSCP_TC_SHIFT(i);
		dscp_tc[j] = req1[i >> 1] >> HCLGE_DSCP_TC_SHIFT(i);
		dscp_tc[i] &= HCLGE_DBG_TC_MASK;
		dscp_tc[j] &= HCLGE_DBG_TC_MASK;
	}

	for (i = 0; i < HNAE3_MAX_DSCP; i++) {
		if (kinfo->dscp_prio[i] == HNAE3_PRIO_ID_INVALID)
			continue;

		seq_printf(s, " %2u    %u    %u\n", i, kinfo->dscp_prio[i],
			   dscp_tc[i]);
	}

	return 0;
}

static int hclge_dbg_dump_tx_buf_cfg(struct hclge_dev *hdev, struct seq_file *s)
{
	struct hclge_tx_buff_alloc_cmd *tx_buf_cmd;
	struct hclge_desc desc;
	int i, ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_TX_BUFF_ALLOC, true);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump tx buf, ret = %d\n", ret);
		return ret;
	}

	tx_buf_cmd = (struct hclge_tx_buff_alloc_cmd *)desc.data;
	for (i = 0; i < HCLGE_MAX_TC_NUM; i++)
		seq_printf(s, "tx_packet_buf_tc_%d: 0x%x\n", i,
			   le16_to_cpu(tx_buf_cmd->tx_pkt_buff[i]));

	return 0;
}

static int hclge_dbg_dump_rx_priv_buf_cfg(struct hclge_dev *hdev,
					  struct seq_file *s)
{
	struct hclge_rx_priv_buff_cmd *rx_buf_cmd;
	struct hclge_desc desc;
	int i, ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_RX_PRIV_BUFF_ALLOC, true);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump rx priv buf, ret = %d\n", ret);
		return ret;
	}

	seq_puts(s, "\n");

	rx_buf_cmd = (struct hclge_rx_priv_buff_cmd *)desc.data;
	for (i = 0; i < HCLGE_MAX_TC_NUM; i++)
		seq_printf(s, "rx_packet_buf_tc_%d: 0x%x\n", i,
			   le16_to_cpu(rx_buf_cmd->buf_num[i]));

	seq_printf(s, "rx_share_buf: 0x%x\n",
		   le16_to_cpu(rx_buf_cmd->shared_buf));

	return 0;
}

static int hclge_dbg_dump_rx_common_wl_cfg(struct hclge_dev *hdev,
					   struct seq_file *s)
{
	struct hclge_rx_com_wl *rx_com_wl;
	struct hclge_desc desc;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_RX_COM_WL_ALLOC, true);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump rx common wl, ret = %d\n", ret);
		return ret;
	}

	rx_com_wl = (struct hclge_rx_com_wl *)desc.data;
	seq_puts(s, "\n");
	seq_printf(s, "rx_com_wl: high: 0x%x, low: 0x%x\n",
		   le16_to_cpu(rx_com_wl->com_wl.high),
		   le16_to_cpu(rx_com_wl->com_wl.low));

	return 0;
}

static int hclge_dbg_dump_rx_global_pkt_cnt(struct hclge_dev *hdev,
					    struct seq_file *s)
{
	struct hclge_rx_com_wl *rx_packet_cnt;
	struct hclge_desc desc;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_RX_GBL_PKT_CNT, true);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump rx global pkt cnt, ret = %d\n", ret);
		return ret;
	}

	rx_packet_cnt = (struct hclge_rx_com_wl *)desc.data;
	seq_printf(s, "rx_global_packet_cnt: high: 0x%x, low: 0x%x\n",
		   le16_to_cpu(rx_packet_cnt->com_wl.high),
		   le16_to_cpu(rx_packet_cnt->com_wl.low));

	return 0;
}

static int hclge_dbg_dump_rx_priv_wl_buf_cfg(struct hclge_dev *hdev,
					     struct seq_file *s)
{
	struct hclge_rx_priv_wl_buf *rx_priv_wl;
	struct hclge_desc desc[2];
	int i, ret;

	hclge_cmd_setup_basic_desc(&desc[0], HCLGE_OPC_RX_PRIV_WL_ALLOC, true);
	desc[0].flag |= cpu_to_le16(HCLGE_COMM_CMD_FLAG_NEXT);
	hclge_cmd_setup_basic_desc(&desc[1], HCLGE_OPC_RX_PRIV_WL_ALLOC, true);
	ret = hclge_cmd_send(&hdev->hw, desc, 2);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump rx priv wl buf, ret = %d\n", ret);
		return ret;
	}

	rx_priv_wl = (struct hclge_rx_priv_wl_buf *)desc[0].data;
	for (i = 0; i < HCLGE_TC_NUM_ONE_DESC; i++)
		seq_printf(s, "rx_priv_wl_tc_%d: high: 0x%x, low: 0x%x\n", i,
			   le16_to_cpu(rx_priv_wl->tc_wl[i].high),
			   le16_to_cpu(rx_priv_wl->tc_wl[i].low));

	rx_priv_wl = (struct hclge_rx_priv_wl_buf *)desc[1].data;
	for (i = 0; i < HCLGE_TC_NUM_ONE_DESC; i++)
		seq_printf(s, "rx_priv_wl_tc_%d: high: 0x%x, low: 0x%x\n",
			   i + HCLGE_TC_NUM_ONE_DESC,
			   le16_to_cpu(rx_priv_wl->tc_wl[i].high),
			   le16_to_cpu(rx_priv_wl->tc_wl[i].low));

	return 0;
}

static int hclge_dbg_dump_rx_common_threshold_cfg(struct hclge_dev *hdev,
						  struct seq_file *s)
{
	struct hclge_rx_com_thrd *rx_com_thrd;
	struct hclge_desc desc[2];
	int i, ret;

	hclge_cmd_setup_basic_desc(&desc[0], HCLGE_OPC_RX_COM_THRD_ALLOC, true);
	desc[0].flag |= cpu_to_le16(HCLGE_COMM_CMD_FLAG_NEXT);
	hclge_cmd_setup_basic_desc(&desc[1], HCLGE_OPC_RX_COM_THRD_ALLOC, true);
	ret = hclge_cmd_send(&hdev->hw, desc, 2);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump rx common threshold, ret = %d\n", ret);
		return ret;
	}

	seq_puts(s, "\n");
	rx_com_thrd = (struct hclge_rx_com_thrd *)desc[0].data;
	for (i = 0; i < HCLGE_TC_NUM_ONE_DESC; i++)
		seq_printf(s, "rx_com_thrd_tc_%d: high: 0x%x, low: 0x%x\n", i,
			   le16_to_cpu(rx_com_thrd->com_thrd[i].high),
			   le16_to_cpu(rx_com_thrd->com_thrd[i].low));

	rx_com_thrd = (struct hclge_rx_com_thrd *)desc[1].data;
	for (i = 0; i < HCLGE_TC_NUM_ONE_DESC; i++)
		seq_printf(s, "rx_com_thrd_tc_%d: high: 0x%x, low: 0x%x\n",
			   i + HCLGE_TC_NUM_ONE_DESC,
			   le16_to_cpu(rx_com_thrd->com_thrd[i].high),
			   le16_to_cpu(rx_com_thrd->com_thrd[i].low));

	return 0;
}

static int hclge_dbg_dump_qos_buf_cfg(struct seq_file *s, void *data)
{
	struct hclge_dev *hdev = hclge_seq_file_to_hdev(s);
	int ret;

	ret = hclge_dbg_dump_tx_buf_cfg(hdev, s);
	if (ret < 0)
		return ret;

	ret = hclge_dbg_dump_rx_priv_buf_cfg(hdev, s);
	if (ret < 0)
		return ret;

	ret = hclge_dbg_dump_rx_common_wl_cfg(hdev, s);
	if (ret < 0)
		return ret;

	ret = hclge_dbg_dump_rx_global_pkt_cnt(hdev, s);
	if (ret < 0)
		return ret;

	seq_puts(s, "\n");
	if (!hnae3_dev_dcb_supported(hdev))
		return 0;

	ret = hclge_dbg_dump_rx_priv_wl_buf_cfg(hdev, s);
	if (ret < 0)
		return ret;

	ret = hclge_dbg_dump_rx_common_threshold_cfg(hdev, s);
	if (ret < 0)
		return ret;

	return 0;
}

static int hclge_dbg_dump_mng_table(struct seq_file *s, void *data)
{
	struct hclge_dev *hdev = hclge_seq_file_to_hdev(s);
	struct hclge_mac_ethertype_idx_rd_cmd *req0;
	struct hclge_desc desc;
	u32 msg_egress_port;
	int ret, i;

	seq_puts(s, "entry  mac_addr          mask  ether  ");
	seq_puts(s, "mask  vlan  mask  i_map  i_dir  e_type  ");
	seq_puts(s, "pf_id  vf_id  q_id  drop\n");

	for (i = 0; i < HCLGE_DBG_MNG_TBL_MAX; i++) {
		hclge_cmd_setup_basic_desc(&desc, HCLGE_MAC_ETHERTYPE_IDX_RD,
					   true);
		req0 = (struct hclge_mac_ethertype_idx_rd_cmd *)desc.data;
		req0->index = cpu_to_le16(i);

		ret = hclge_cmd_send(&hdev->hw, &desc, 1);
		if (ret) {
			dev_err(&hdev->pdev->dev,
				"failed to dump manage table, ret = %d\n", ret);
			return ret;
		}

		if (!req0->resp_code)
			continue;

		seq_printf(s, "%02u     %pM ",
			   le16_to_cpu(req0->index), req0->mac_addr);

		seq_printf(s, "%x     %04x   %x     %04x  ",
			   !!(req0->flags & HCLGE_DBG_MNG_MAC_MASK_B),
			   le16_to_cpu(req0->ethter_type),
			   !!(req0->flags & HCLGE_DBG_MNG_ETHER_MASK_B),
			   le16_to_cpu(req0->vlan_tag) &
			   HCLGE_DBG_MNG_VLAN_TAG);

		seq_printf(s, "%x     %02x     %02x     ",
			   !!(req0->flags & HCLGE_DBG_MNG_VLAN_MASK_B),
			   req0->i_port_bitmap, req0->i_port_direction);

		msg_egress_port = le16_to_cpu(req0->egress_port);
		seq_printf(s, "%x       %x      %02x     %04x  %x\n",
			   !!(msg_egress_port & HCLGE_DBG_MNG_E_TYPE_B),
			   msg_egress_port & HCLGE_DBG_MNG_PF_ID,
			   (msg_egress_port >> 3) & HCLGE_DBG_MNG_VF_ID,
			   le16_to_cpu(req0->egress_queue),
			   !!(msg_egress_port & HCLGE_DBG_MNG_DROP_B));
	}

	return 0;
}

static int hclge_dbg_fd_tcam_read(struct hclge_dev *hdev, bool sel_x,
				  struct seq_file *s,
				  struct hclge_dbg_tcam_msg tcam_msg)
{
	struct hclge_fd_tcam_config_1_cmd *req1;
	struct hclge_fd_tcam_config_2_cmd *req2;
	struct hclge_fd_tcam_config_3_cmd *req3;
	struct hclge_desc desc[3];
	int ret, i;
	__le32 *req;

	hclge_cmd_setup_basic_desc(&desc[0], HCLGE_OPC_FD_TCAM_OP, true);
	desc[0].flag |= cpu_to_le16(HCLGE_COMM_CMD_FLAG_NEXT);
	hclge_cmd_setup_basic_desc(&desc[1], HCLGE_OPC_FD_TCAM_OP, true);
	desc[1].flag |= cpu_to_le16(HCLGE_COMM_CMD_FLAG_NEXT);
	hclge_cmd_setup_basic_desc(&desc[2], HCLGE_OPC_FD_TCAM_OP, true);

	req1 = (struct hclge_fd_tcam_config_1_cmd *)desc[0].data;
	req2 = (struct hclge_fd_tcam_config_2_cmd *)desc[1].data;
	req3 = (struct hclge_fd_tcam_config_3_cmd *)desc[2].data;

	req1->stage  = tcam_msg.stage;
	req1->xy_sel = sel_x ? 1 : 0;
	req1->index  = cpu_to_le32(tcam_msg.loc);

	ret = hclge_cmd_send(&hdev->hw, desc, 3);
	if (ret)
		return ret;

	seq_printf(s, "read result tcam key %s(%u):\n",
		   sel_x ? "x" : "y", tcam_msg.loc);

	/* tcam_data0 ~ tcam_data1 */
	req = (__le32 *)req1->tcam_data;
	for (i = 0; i < 2; i++)
		seq_printf(s, "%08x\n", le32_to_cpu(*req++));

	/* tcam_data2 ~ tcam_data7 */
	req = (__le32 *)req2->tcam_data;
	for (i = 0; i < 6; i++)
		seq_printf(s, "%08x\n", le32_to_cpu(*req++));

	/* tcam_data8 ~ tcam_data12 */
	req = (__le32 *)req3->tcam_data;
	for (i = 0; i < 5; i++)
		seq_printf(s, "%08x\n", le32_to_cpu(*req++));

	return ret;
}

static int hclge_dbg_get_rules_location(struct hclge_dev *hdev, u16 *rule_locs)
{
	struct hclge_fd_rule *rule;
	struct hlist_node *node;
	int cnt = 0;

	spin_lock_bh(&hdev->fd_rule_lock);
	hlist_for_each_entry_safe(rule, node, &hdev->fd_rule_list, rule_node) {
		rule_locs[cnt] = rule->location;
		cnt++;
	}
	spin_unlock_bh(&hdev->fd_rule_lock);

	if (cnt != hdev->hclge_fd_rule_num || cnt == 0)
		return -EINVAL;

	return cnt;
}

static int hclge_dbg_dump_fd_tcam(struct seq_file *s, void *data)
{
	struct hclge_dev *hdev = hclge_seq_file_to_hdev(s);
	struct hclge_dbg_tcam_msg tcam_msg;
	int i, ret, rule_cnt;
	u16 *rule_locs;
	u32 rule_num;

	if (!hnae3_ae_dev_fd_supported(hdev->ae_dev)) {
		dev_err(&hdev->pdev->dev,
			"Only FD-supported dev supports dump fd tcam\n");
		return -EOPNOTSUPP;
	}

	rule_num = hdev->fd_cfg.rule_num[HCLGE_FD_STAGE_1];
	if (!hdev->hclge_fd_rule_num || !rule_num)
		return 0;

	rule_locs = kcalloc(rule_num, sizeof(u16), GFP_KERNEL);
	if (!rule_locs)
		return -ENOMEM;

	rule_cnt = hclge_dbg_get_rules_location(hdev, rule_locs);
	if (rule_cnt < 0) {
		ret = rule_cnt;
		dev_err(&hdev->pdev->dev,
			"failed to get rule number, ret = %d\n", ret);
		goto out;
	}

	ret = 0;
	for (i = 0; i < rule_cnt; i++) {
		tcam_msg.stage = HCLGE_FD_STAGE_1;
		tcam_msg.loc = rule_locs[i];

		ret = hclge_dbg_fd_tcam_read(hdev, true, s, tcam_msg);
		if (ret) {
			dev_err(&hdev->pdev->dev,
				"failed to get fd tcam key x, ret = %d\n", ret);
			goto out;
		}

		ret = hclge_dbg_fd_tcam_read(hdev, false, s, tcam_msg);
		if (ret) {
			dev_err(&hdev->pdev->dev,
				"failed to get fd tcam key y, ret = %d\n", ret);
			goto out;
		}

	}

out:
	kfree(rule_locs);
	return ret;
}

static int hclge_dbg_dump_fd_counter(struct seq_file *s, void *data)
{
	struct hclge_dev *hdev = hclge_seq_file_to_hdev(s);
	u8 func_num = pci_num_vf(hdev->pdev) + 1; /* pf and enabled vf num */
	struct hclge_fd_ad_cnt_read_cmd *req;
	char str_id[HCLGE_DBG_ID_LEN];
	struct hclge_desc desc;
	int ret;
	u64 cnt;
	u8 i;

	if (!hnae3_ae_dev_fd_supported(hdev->ae_dev))
		return -EOPNOTSUPP;

	seq_puts(s, "func_id\thit_times\n");

	for (i = 0; i < func_num; i++) {
		hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_FD_CNT_OP, true);
		req = (struct hclge_fd_ad_cnt_read_cmd *)desc.data;
		req->index = cpu_to_le16(i);
		ret = hclge_cmd_send(&hdev->hw, &desc, 1);
		if (ret) {
			dev_err(&hdev->pdev->dev, "failed to get fd counter, ret = %d\n",
				ret);
			return ret;
		}
		cnt = le64_to_cpu(req->cnt);
		hclge_dbg_get_func_id_str(str_id, i);
		seq_printf(s, "%s\t%llu\n", str_id, cnt);
	}

	return 0;
}

static const struct hclge_dbg_status_dfx_info hclge_dbg_rst_info[] = {
	{HCLGE_MISC_VECTOR_REG_BASE, "vector0 interrupt enable status"},
	{HCLGE_MISC_RESET_STS_REG,   "reset interrupt source"},
	{HCLGE_MISC_VECTOR_INT_STS,  "reset interrupt status"},
	{HCLGE_RAS_PF_OTHER_INT_STS_REG, "RAS interrupt status"},
	{HCLGE_GLOBAL_RESET_REG,  "hardware reset status"},
	{HCLGE_NIC_CSQ_DEPTH_REG, "handshake status"},
	{HCLGE_FUN_RST_ING, "function reset status"}
};

int hclge_dbg_dump_rst_info(struct hclge_dev *hdev, char *buf, int len)
{
	u32 i, offset;
	int pos = 0;

	pos += scnprintf(buf + pos, len - pos, "PF reset count: %u\n",
			 hdev->rst_stats.pf_rst_cnt);
	pos += scnprintf(buf + pos, len - pos, "FLR reset count: %u\n",
			 hdev->rst_stats.flr_rst_cnt);
	pos += scnprintf(buf + pos, len - pos, "GLOBAL reset count: %u\n",
			 hdev->rst_stats.global_rst_cnt);
	pos += scnprintf(buf + pos, len - pos, "IMP reset count: %u\n",
			 hdev->rst_stats.imp_rst_cnt);
	pos += scnprintf(buf + pos, len - pos, "reset done count: %u\n",
			 hdev->rst_stats.reset_done_cnt);
	pos += scnprintf(buf + pos, len - pos, "HW reset done count: %u\n",
			 hdev->rst_stats.hw_reset_done_cnt);
	pos += scnprintf(buf + pos, len - pos, "reset count: %u\n",
			 hdev->rst_stats.reset_cnt);
	pos += scnprintf(buf + pos, len - pos, "reset fail count: %u\n",
			 hdev->rst_stats.reset_fail_cnt);

	for (i = 0; i < ARRAY_SIZE(hclge_dbg_rst_info); i++) {
		offset = hclge_dbg_rst_info[i].offset;
		pos += scnprintf(buf + pos, len - pos, "%s: 0x%x\n",
				 hclge_dbg_rst_info[i].message,
				 hclge_read_dev(&hdev->hw, offset));
	}

	pos += scnprintf(buf + pos, len - pos, "hdev state: 0x%lx\n",
			 hdev->state);

	return 0;
}

static int hclge_dbg_seq_dump_rst_info(struct seq_file *s, void *data)
{
	struct hclge_dev *hdev = hclge_seq_file_to_hdev(s);
	u32 i, offset;

	seq_printf(s, "PF reset count: %u\n", hdev->rst_stats.pf_rst_cnt);
	seq_printf(s, "FLR reset count: %u\n", hdev->rst_stats.flr_rst_cnt);
	seq_printf(s, "GLOBAL reset count: %u\n",
		   hdev->rst_stats.global_rst_cnt);
	seq_printf(s, "IMP reset count: %u\n", hdev->rst_stats.imp_rst_cnt);
	seq_printf(s, "reset done count: %u\n", hdev->rst_stats.reset_done_cnt);
	seq_printf(s, "HW reset done count: %u\n",
		   hdev->rst_stats.hw_reset_done_cnt);
	seq_printf(s, "reset count: %u\n", hdev->rst_stats.reset_cnt);
	seq_printf(s, "reset fail count: %u\n", hdev->rst_stats.reset_fail_cnt);

	for (i = 0; i < ARRAY_SIZE(hclge_dbg_rst_info); i++) {
		offset = hclge_dbg_rst_info[i].offset;
		seq_printf(s, "%s: 0x%x\n",
			   hclge_dbg_rst_info[i].message,
			   hclge_read_dev(&hdev->hw, offset));
	}

	seq_printf(s, "hdev state: 0x%lx\n", hdev->state);

	return 0;
}

static int hclge_dbg_dump_serv_info(struct seq_file *s, void *data)
{
	struct hclge_dev *hdev = hclge_seq_file_to_hdev(s);
	unsigned long rem_nsec;
	u64 lc;

	lc = local_clock();
	rem_nsec = do_div(lc, HCLGE_BILLION_NANO_SECONDS);

	seq_printf(s, "local_clock: [%5lu.%06lu]\n",
		   (unsigned long)lc, rem_nsec / 1000);
	seq_printf(s, "delta: %u(ms)\n",
		   jiffies_to_msecs(jiffies - hdev->last_serv_processed));
	seq_printf(s, "last_service_task_processed: %lu(jiffies)\n",
		   hdev->last_serv_processed);
	seq_printf(s, "last_service_task_cnt: %lu\n", hdev->serv_processed_cnt);

	return 0;
}

static int hclge_dbg_dump_interrupt(struct seq_file *s, void *data)
{
	struct hclge_dev *hdev = hclge_seq_file_to_hdev(s);

	seq_printf(s, "num_nic_msi: %u\n", hdev->num_nic_msi);
	seq_printf(s, "num_roce_msi: %u\n", hdev->num_roce_msi);
	seq_printf(s, "num_msi_used: %u\n", hdev->num_msi_used);
	seq_printf(s, "num_msi_left: %u\n", hdev->num_msi_left);

	return 0;
}

static void hclge_dbg_imp_info_data_print(struct seq_file *s,
					  struct hclge_desc *desc_src,
					  u32 bd_num)
{
#define HCLGE_DBG_IMP_INFO_PRINT_OFFSET 0x2

	struct hclge_desc *desc_index = desc_src;
	u32 offset = 0;
	u32 i, j;

	seq_puts(s, "offset | data\n");

	for (i = 0; i < bd_num; i++) {
		j = 0;
		while (j < HCLGE_DESC_DATA_LEN - 1) {
			seq_printf(s, "0x%04x | ", offset);
			seq_printf(s, "0x%08x  ",
				   le32_to_cpu(desc_index->data[j++]));
			seq_printf(s, "0x%08x\n",
				   le32_to_cpu(desc_index->data[j++]));
			offset += sizeof(u32) * HCLGE_DBG_IMP_INFO_PRINT_OFFSET;
		}
		desc_index++;
	}
}

static int hclge_dbg_get_imp_stats_info(struct seq_file *s, void *data)
{
	struct hclge_dev *hdev = hclge_seq_file_to_hdev(s);
	struct hclge_get_imp_bd_cmd *req;
	struct hclge_desc *desc_src;
	struct hclge_desc desc;
	u32 bd_num;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_IMP_STATS_BD, true);

	req = (struct hclge_get_imp_bd_cmd *)desc.data;
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to get imp statistics bd number, ret = %d\n",
			ret);
		return ret;
	}

	bd_num = le32_to_cpu(req->bd_num);
	if (!bd_num) {
		dev_err(&hdev->pdev->dev, "imp statistics bd number is 0!\n");
		return -EINVAL;
	}

	desc_src = kcalloc(bd_num, sizeof(struct hclge_desc), GFP_KERNEL);
	if (!desc_src)
		return -ENOMEM;

	ret  = hclge_dbg_cmd_send(hdev, desc_src, 0, bd_num,
				  HCLGE_OPC_IMP_STATS_INFO);
	if (ret) {
		kfree(desc_src);
		dev_err(&hdev->pdev->dev,
			"failed to get imp statistics, ret = %d\n", ret);
		return ret;
	}

	hclge_dbg_imp_info_data_print(s, desc_src, bd_num);

	kfree(desc_src);

	return 0;
}

#define HCLGE_CMD_NCL_CONFIG_BD_NUM	5
#define HCLGE_MAX_NCL_CONFIG_LENGTH	16384

static void hclge_ncl_config_data_print(struct hclge_desc *desc, int *index,
					struct seq_file *s)
{
#define HCLGE_CMD_DATA_NUM		6

	int offset = HCLGE_MAX_NCL_CONFIG_LENGTH - *index;
	int i, j;

	for (i = 0; i < HCLGE_CMD_NCL_CONFIG_BD_NUM; i++) {
		for (j = 0; j < HCLGE_CMD_DATA_NUM; j++) {
			if (i == 0 && j == 0)
				continue;

			seq_printf(s, "0x%04x | 0x%08x\n", offset,
				   le32_to_cpu(desc[i].data[j]));

			offset += sizeof(u32);
			*index -= sizeof(u32);

			if (*index <= 0)
				return;
		}
	}
}

static int hclge_dbg_dump_ncl_config(struct seq_file *s, void *data)
{
#define HCLGE_NCL_CONFIG_LENGTH_IN_EACH_CMD	(20 + 24 * 4)

	struct hclge_desc desc[HCLGE_CMD_NCL_CONFIG_BD_NUM];
	struct hclge_dev *hdev = hclge_seq_file_to_hdev(s);
	int bd_num = HCLGE_CMD_NCL_CONFIG_BD_NUM;
	int index = HCLGE_MAX_NCL_CONFIG_LENGTH;
	u32 data0;
	int ret;

	seq_puts(s, "offset | data\n");

	while (index > 0) {
		data0 = HCLGE_MAX_NCL_CONFIG_LENGTH - index;
		if (index >= HCLGE_NCL_CONFIG_LENGTH_IN_EACH_CMD)
			data0 |= HCLGE_NCL_CONFIG_LENGTH_IN_EACH_CMD << 16;
		else
			data0 |= (u32)index << 16;
		ret = hclge_dbg_cmd_send(hdev, desc, data0, bd_num,
					 HCLGE_OPC_QUERY_NCL_CONFIG);
		if (ret)
			return ret;

		hclge_ncl_config_data_print(desc, &index, s);
	}

	return 0;
}

static int hclge_dbg_dump_loopback(struct seq_file *s, void *data)
{
	struct hclge_dev *hdev = hclge_seq_file_to_hdev(s);
	struct phy_device *phydev = hdev->hw.mac.phydev;
	struct hclge_config_mac_mode_cmd *req_app;
	struct hclge_common_lb_cmd *req_common;
	struct hclge_desc desc;
	u8 loopback_en;
	int ret;

	req_app = (struct hclge_config_mac_mode_cmd *)desc.data;
	req_common = (struct hclge_common_lb_cmd *)desc.data;

	seq_printf(s, "mac id: %u\n", hdev->hw.mac.mac_id);

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_CONFIG_MAC_MODE, true);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump app loopback status, ret = %d\n", ret);
		return ret;
	}

	loopback_en = hnae3_get_bit(le32_to_cpu(req_app->txrx_pad_fcs_loop_en),
				    HCLGE_MAC_APP_LP_B);
	seq_printf(s, "app loopback: %s\n", str_on_off(loopback_en));

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_COMMON_LOOPBACK, true);
	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to dump common loopback status, ret = %d\n",
			ret);
		return ret;
	}

	loopback_en = req_common->enable &
		      HCLGE_CMD_SERDES_SERIAL_INNER_LOOP_B;
	seq_printf(s, "serdes serial loopback: %s\n", str_on_off(loopback_en));

	loopback_en = req_common->enable &
		      HCLGE_CMD_SERDES_PARALLEL_INNER_LOOP_B ? 1 : 0;
	seq_printf(s, "serdes parallel loopback: %s\n",
		   str_on_off(loopback_en));

	if (phydev) {
		loopback_en = phydev->loopback_enabled;
		seq_printf(s, "phy loopback: %s\n", str_on_off(loopback_en));
	} else if (hnae3_dev_phy_imp_supported(hdev)) {
		loopback_en = req_common->enable &
			      HCLGE_CMD_GE_PHY_INNER_LOOP_B;
		seq_printf(s, "phy loopback: %s\n", str_on_off(loopback_en));
	}

	return 0;
}

/* hclge_dbg_dump_mac_tnl_status: print message about mac tnl interrupt
 * @hdev: pointer to struct hclge_dev
 */
static int hclge_dbg_dump_mac_tnl_status(struct seq_file *s, void *data)
{
	struct hclge_dev *hdev = hclge_seq_file_to_hdev(s);
	struct hclge_mac_tnl_stats stats;
	unsigned long rem_nsec;

	seq_puts(s, "Recently generated mac tnl interruption:\n");

	while (kfifo_get(&hdev->mac_tnl_log, &stats)) {
		rem_nsec = do_div(stats.time, HCLGE_BILLION_NANO_SECONDS);

		seq_printf(s, "[%07lu.%03lu] status = 0x%x\n",
			   (unsigned long)stats.time, rem_nsec / 1000,
			   stats.status);
	}

	return 0;
}

static void hclge_dbg_dump_mac_list(struct seq_file *s, bool is_unicast)
{
	struct hclge_dev *hdev = hclge_seq_file_to_hdev(s);
	struct hclge_mac_node *mac_node, *tmp;
	struct hclge_vport *vport;
	struct list_head *list;
	u32 func_id;

	seq_printf(s, "%s MAC_LIST:\n", is_unicast ? "UC" : "MC");
	seq_puts(s, "FUNC_ID  MAC_ADDR            STATE\n");

	for (func_id = 0; func_id < hdev->num_alloc_vport; func_id++) {
		vport = &hdev->vport[func_id];
		list = is_unicast ? &vport->uc_mac_list : &vport->mc_mac_list;
		spin_lock_bh(&vport->mac_list_lock);
		list_for_each_entry_safe(mac_node, tmp, list, node) {
			if (func_id)
				seq_printf(s, "vf%-7u", func_id - 1U);
			else
				seq_puts(s, "pf       ");
			seq_printf(s, "%pM   ", mac_node->mac_addr);
			seq_printf(s, "%5s\n",
				   hclge_mac_state_str[mac_node->state]);
		}
		spin_unlock_bh(&vport->mac_list_lock);
	}
}

static int hclge_dbg_dump_umv_info(struct seq_file *s, void *data)
{
	struct hclge_dev *hdev = hclge_seq_file_to_hdev(s);
	u8 func_num = pci_num_vf(hdev->pdev) + 1;
	struct hclge_vport *vport;
	u8 i;

	seq_printf(s, "num_alloc_vport   : %u\n", hdev->num_alloc_vport);
	seq_printf(s, "max_umv_size     : %u\n", hdev->max_umv_size);
	seq_printf(s, "wanted_umv_size  : %u\n", hdev->wanted_umv_size);
	seq_printf(s, "priv_umv_size    : %u\n", hdev->priv_umv_size);

	mutex_lock(&hdev->vport_lock);
	seq_printf(s, "share_umv_size   : %u\n", hdev->share_umv_size);
	for (i = 0; i < func_num; i++) {
		vport = &hdev->vport[i];
		seq_printf(s, "vport(%u) used_umv_num : %u\n",
			   i, vport->used_umv_num);
	}
	mutex_unlock(&hdev->vport_lock);

	seq_printf(s, "used_mc_mac_num  : %u\n", hdev->used_mc_mac_num);

	return 0;
}

static int hclge_get_vlan_rx_offload_cfg(struct hclge_dev *hdev, u8 vf_id,
					 struct hclge_dbg_vlan_cfg *vlan_cfg)
{
	struct hclge_vport_vtag_rx_cfg_cmd *req;
	struct hclge_desc desc;
	u16 bmap_index;
	u8 rx_cfg;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_VLAN_PORT_RX_CFG, true);

	req = (struct hclge_vport_vtag_rx_cfg_cmd *)desc.data;
	req->vf_offset = vf_id / HCLGE_VF_NUM_PER_CMD;
	bmap_index = vf_id % HCLGE_VF_NUM_PER_CMD / HCLGE_VF_NUM_PER_BYTE;
	req->vf_bitmap[bmap_index] = 1U << (vf_id % HCLGE_VF_NUM_PER_BYTE);

	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to get vport%u rxvlan cfg, ret = %d\n",
			vf_id, ret);
		return ret;
	}

	rx_cfg = req->vport_vlan_cfg;
	vlan_cfg->strip_tag1 = hnae3_get_bit(rx_cfg, HCLGE_REM_TAG1_EN_B);
	vlan_cfg->strip_tag2 = hnae3_get_bit(rx_cfg, HCLGE_REM_TAG2_EN_B);
	vlan_cfg->drop_tag1 = hnae3_get_bit(rx_cfg, HCLGE_DISCARD_TAG1_EN_B);
	vlan_cfg->drop_tag2 = hnae3_get_bit(rx_cfg, HCLGE_DISCARD_TAG2_EN_B);
	vlan_cfg->pri_only1 = hnae3_get_bit(rx_cfg, HCLGE_SHOW_TAG1_EN_B);
	vlan_cfg->pri_only2 = hnae3_get_bit(rx_cfg, HCLGE_SHOW_TAG2_EN_B);

	return 0;
}

static int hclge_get_vlan_tx_offload_cfg(struct hclge_dev *hdev, u8 vf_id,
					 struct hclge_dbg_vlan_cfg *vlan_cfg)
{
	struct hclge_vport_vtag_tx_cfg_cmd *req;
	struct hclge_desc desc;
	u16 bmap_index;
	u8 tx_cfg;
	int ret;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_VLAN_PORT_TX_CFG, true);
	req = (struct hclge_vport_vtag_tx_cfg_cmd *)desc.data;
	req->vf_offset = vf_id / HCLGE_VF_NUM_PER_CMD;
	bmap_index = vf_id % HCLGE_VF_NUM_PER_CMD / HCLGE_VF_NUM_PER_BYTE;
	req->vf_bitmap[bmap_index] = 1U << (vf_id % HCLGE_VF_NUM_PER_BYTE);

	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to get vport%u txvlan cfg, ret = %d\n",
			vf_id, ret);
		return ret;
	}

	tx_cfg = req->vport_vlan_cfg;
	vlan_cfg->pvid = le16_to_cpu(req->def_vlan_tag1);

	vlan_cfg->accept_tag1 = hnae3_get_bit(tx_cfg, HCLGE_ACCEPT_TAG1_B);
	vlan_cfg->accept_tag2 = hnae3_get_bit(tx_cfg, HCLGE_ACCEPT_TAG2_B);
	vlan_cfg->accept_untag1 = hnae3_get_bit(tx_cfg, HCLGE_ACCEPT_UNTAG1_B);
	vlan_cfg->accept_untag2 = hnae3_get_bit(tx_cfg, HCLGE_ACCEPT_UNTAG2_B);
	vlan_cfg->insert_tag1 = hnae3_get_bit(tx_cfg, HCLGE_PORT_INS_TAG1_EN_B);
	vlan_cfg->insert_tag2 = hnae3_get_bit(tx_cfg, HCLGE_PORT_INS_TAG2_EN_B);
	vlan_cfg->shift_tag = hnae3_get_bit(tx_cfg, HCLGE_TAG_SHIFT_MODE_EN_B);

	return 0;
}

static int hclge_get_vlan_filter_config_cmd(struct hclge_dev *hdev,
					    u8 vlan_type, u8 vf_id,
					    struct hclge_desc *desc)
{
	struct hclge_vlan_filter_ctrl_cmd *req;
	int ret;

	hclge_cmd_setup_basic_desc(desc, HCLGE_OPC_VLAN_FILTER_CTRL, true);
	req = (struct hclge_vlan_filter_ctrl_cmd *)desc->data;
	req->vlan_type = vlan_type;
	req->vf_id = vf_id;

	ret = hclge_cmd_send(&hdev->hw, desc, 1);
	if (ret)
		dev_err(&hdev->pdev->dev,
			"failed to get vport%u vlan filter config, ret = %d.\n",
			vf_id, ret);

	return ret;
}

static int hclge_get_vlan_filter_state(struct hclge_dev *hdev, u8 vlan_type,
				       u8 vf_id, u8 *vlan_fe)
{
	struct hclge_vlan_filter_ctrl_cmd *req;
	struct hclge_desc desc;
	int ret;

	ret = hclge_get_vlan_filter_config_cmd(hdev, vlan_type, vf_id, &desc);
	if (ret)
		return ret;

	req = (struct hclge_vlan_filter_ctrl_cmd *)desc.data;
	*vlan_fe = req->vlan_fe;

	return 0;
}

static int hclge_get_port_vlan_filter_bypass_state(struct hclge_dev *hdev,
						   u8 vf_id, u8 *bypass_en)
{
	struct hclge_port_vlan_filter_bypass_cmd *req;
	struct hclge_desc desc;
	int ret;

	if (!test_bit(HNAE3_DEV_SUPPORT_PORT_VLAN_BYPASS_B, hdev->ae_dev->caps))
		return 0;

	hclge_cmd_setup_basic_desc(&desc, HCLGE_OPC_PORT_VLAN_BYPASS, true);
	req = (struct hclge_port_vlan_filter_bypass_cmd *)desc.data;
	req->vf_id = vf_id;

	ret = hclge_cmd_send(&hdev->hw, &desc, 1);
	if (ret) {
		dev_err(&hdev->pdev->dev,
			"failed to get vport%u port vlan filter bypass state, ret = %d.\n",
			vf_id, ret);
		return ret;
	}

	*bypass_en = hnae3_get_bit(req->bypass_state, HCLGE_INGRESS_BYPASS_B);

	return 0;
}

static int hclge_dbg_dump_vlan_filter_config(struct hclge_dev *hdev,
					     struct seq_file *s)
{
	u8 func_num = pci_num_vf(hdev->pdev) + 1; /* pf and enabled vf num */
	u8 i, vlan_fe, bypass, ingress, egress;
	char str_id[HCLGE_DBG_ID_LEN];
	int ret;

	ret = hclge_get_vlan_filter_state(hdev, HCLGE_FILTER_TYPE_PORT, 0,
					  &vlan_fe);
	if (ret)
		return ret;
	ingress = vlan_fe & HCLGE_FILTER_FE_NIC_INGRESS_B;
	egress = vlan_fe & HCLGE_FILTER_FE_NIC_EGRESS_B ? 1 : 0;

	seq_printf(s, "I_PORT_VLAN_FILTER: %s\n", str_on_off(ingress));
	seq_printf(s, "E_PORT_VLAN_FILTER: %s\n", str_on_off(egress));

	seq_puts(s, "FUNC_ID  I_VF_VLAN_FILTER  E_VF_VLAN_FILTER  ");
	seq_puts(s, "PORT_VLAN_FILTER_BYPASS\n");

	for (i = 0; i < func_num; i++) {
		ret = hclge_get_vlan_filter_state(hdev, HCLGE_FILTER_TYPE_VF, i,
						  &vlan_fe);
		if (ret)
			return ret;

		ingress = vlan_fe & HCLGE_FILTER_FE_NIC_INGRESS_B;
		egress = vlan_fe & HCLGE_FILTER_FE_NIC_EGRESS_B ? 1 : 0;
		ret = hclge_get_port_vlan_filter_bypass_state(hdev, i, &bypass);
		if (ret)
			return ret;

		seq_printf(s, "%-9s%-18s%-18s%s\n",
			   hclge_dbg_get_func_id_str(str_id, i),
			   str_on_off(ingress), str_on_off(egress),
			   test_bit(HNAE3_DEV_SUPPORT_PORT_VLAN_BYPASS_B,
				    hdev->ae_dev->caps) ?
						str_on_off(bypass) : "NA");
	}
	seq_puts(s, "\n");

	return 0;
}

static int hclge_dbg_dump_vlan_offload_config(struct hclge_dev *hdev,
					      struct seq_file *s)
{
	u8 func_num = pci_num_vf(hdev->pdev) + 1; /* pf and enabled vf num */
	struct hclge_dbg_vlan_cfg vlan_cfg;
	char str_id[HCLGE_DBG_ID_LEN];
	int ret;
	u8 i;

	seq_puts(s, "FUNC_ID  PVID  ACCEPT_TAG1  ACCEPT_TAG2 ACCEPT_UNTAG1  ");
	seq_puts(s, "ACCEPT_UNTAG2  INSERT_TAG1  INSERT_TAG2  SHIFT_TAG  ");
	seq_puts(s, "STRIP_TAG1  STRIP_TAG2  DROP_TAG1  DROP_TAG2  ");
	seq_puts(s, "PRI_ONLY_TAG1  PRI_ONLY_TAG2\n");

	for (i = 0; i < func_num; i++) {
		ret = hclge_get_vlan_tx_offload_cfg(hdev, i, &vlan_cfg);
		if (ret)
			return ret;

		ret = hclge_get_vlan_rx_offload_cfg(hdev, i, &vlan_cfg);
		if (ret)
			return ret;

		seq_printf(s, "%-9s", hclge_dbg_get_func_id_str(str_id, i));
		seq_printf(s, "%-6u", vlan_cfg.pvid);
		seq_printf(s, "%-13s", str_on_off(vlan_cfg.accept_tag1));
		seq_printf(s, "%-12s", str_on_off(vlan_cfg.accept_tag2));
		seq_printf(s, "%-15s", str_on_off(vlan_cfg.accept_untag1));
		seq_printf(s, "%-15s", str_on_off(vlan_cfg.accept_untag2));
		seq_printf(s, "%-13s", str_on_off(vlan_cfg.insert_tag1));
		seq_printf(s, "%-13s", str_on_off(vlan_cfg.insert_tag2));
		seq_printf(s, "%-11s", str_on_off(vlan_cfg.shift_tag));
		seq_printf(s, "%-12s", str_on_off(vlan_cfg.strip_tag1));
		seq_printf(s, "%-12s", str_on_off(vlan_cfg.strip_tag2));
		seq_printf(s, "%-11s", str_on_off(vlan_cfg.drop_tag1));
		seq_printf(s, "%-11s", str_on_off(vlan_cfg.drop_tag2));
		seq_printf(s, "%-15s", str_on_off(vlan_cfg.pri_only1));
		seq_printf(s, "%s\n", str_on_off(vlan_cfg.pri_only2));
	}

	return 0;
}

static int hclge_dbg_dump_vlan_config(struct seq_file *s, void *data)
{
	struct hclge_dev *hdev = hclge_seq_file_to_hdev(s);
	int ret;

	ret = hclge_dbg_dump_vlan_filter_config(hdev, s);
	if (ret)
		return ret;

	return hclge_dbg_dump_vlan_offload_config(hdev, s);
}

static int hclge_dbg_dump_ptp_info(struct seq_file *s, void *data)
{
	struct hclge_dev *hdev = hclge_seq_file_to_hdev(s);
	struct hclge_ptp *ptp = hdev->ptp;
	u32 sw_cfg = ptp->ptp_cfg;
	unsigned int tx_start;
	unsigned int last_rx;
	u32 hw_cfg;
	int ret;

	seq_printf(s, "phc %s's debug info:\n", ptp->info.name);
	seq_printf(s, "ptp enable: %s\n",
		   str_yes_no(test_bit(HCLGE_PTP_FLAG_EN, &ptp->flags)));
	seq_printf(s, "ptp tx enable: %s\n",
		   str_yes_no(test_bit(HCLGE_PTP_FLAG_TX_EN, &ptp->flags)));
	seq_printf(s, "ptp rx enable: %s\n",
		   str_yes_no(test_bit(HCLGE_PTP_FLAG_RX_EN, &ptp->flags)));

	last_rx = jiffies_to_msecs(ptp->last_rx);
	seq_printf(s, "last rx time: %lu.%lu\n",
		   last_rx / MSEC_PER_SEC, last_rx % MSEC_PER_SEC);
	seq_printf(s, "rx count: %lu\n", ptp->rx_cnt);

	tx_start = jiffies_to_msecs(ptp->tx_start);
	seq_printf(s, "last tx start time: %lu.%lu\n",
		   tx_start / MSEC_PER_SEC, tx_start % MSEC_PER_SEC);
	seq_printf(s, "tx count: %lu\n", ptp->tx_cnt);
	seq_printf(s, "tx skipped count: %lu\n", ptp->tx_skipped);
	seq_printf(s, "tx timeout count: %lu\n", ptp->tx_timeout);
	seq_printf(s, "last tx seqid: %u\n", ptp->last_tx_seqid);


	ret = hclge_ptp_cfg_qry(hdev, &hw_cfg);
	if (ret)
		return ret;

	seq_printf(s, "sw_cfg: %#x, hw_cfg: %#x\n", sw_cfg, hw_cfg);

	seq_printf(s, "tx type: %d, rx filter: %d\n",
		   ptp->ts_cfg.tx_type, ptp->ts_cfg.rx_filter);

	return 0;
}

static int hclge_dbg_dump_mac_uc(struct seq_file *s, void *data)
{
	hclge_dbg_dump_mac_list(s, true);

	return 0;
}

static int hclge_dbg_dump_mac_mc(struct seq_file *s, void *data)
{
	hclge_dbg_dump_mac_list(s, false);

	return 0;
}

static const struct hclge_dbg_func hclge_dbg_cmd_func[] = {
	{
		.cmd = HNAE3_DBG_CMD_TM_NODES,
		.dbg_read_func = hclge_dbg_dump_tm_nodes,
	},
	{
		.cmd = HNAE3_DBG_CMD_TM_PRI,
		.dbg_read_func = hclge_dbg_dump_tm_pri,
	},
	{
		.cmd = HNAE3_DBG_CMD_TM_QSET,
		.dbg_read_func = hclge_dbg_dump_tm_qset,
	},
	{
		.cmd = HNAE3_DBG_CMD_TM_MAP,
		.dbg_read_func = hclge_dbg_dump_tm_map,
	},
	{
		.cmd = HNAE3_DBG_CMD_TM_PG,
		.dbg_read_func = hclge_dbg_dump_tm_pg,
	},
	{
		.cmd = HNAE3_DBG_CMD_TM_PORT,
		.dbg_read_func = hclge_dbg_dump_tm_port,
	},
	{
		.cmd = HNAE3_DBG_CMD_TC_SCH_INFO,
		.dbg_read_func = hclge_dbg_dump_tc,
	},
	{
		.cmd = HNAE3_DBG_CMD_QOS_PAUSE_CFG,
		.dbg_read_func = hclge_dbg_dump_qos_pause_cfg,
	},
	{
		.cmd = HNAE3_DBG_CMD_QOS_PRI_MAP,
		.dbg_read_func = hclge_dbg_dump_qos_pri_map,
	},
	{
		.cmd = HNAE3_DBG_CMD_QOS_DSCP_MAP,
		.dbg_read_func = hclge_dbg_dump_qos_dscp_map,
	},
	{
		.cmd = HNAE3_DBG_CMD_QOS_BUF_CFG,
		.dbg_read_func = hclge_dbg_dump_qos_buf_cfg,
	},
	{
		.cmd = HNAE3_DBG_CMD_MAC_UC,
		.dbg_read_func = hclge_dbg_dump_mac_uc,
	},
	{
		.cmd = HNAE3_DBG_CMD_MAC_MC,
		.dbg_read_func = hclge_dbg_dump_mac_mc,
	},
	{
		.cmd = HNAE3_DBG_CMD_MNG_TBL,
		.dbg_read_func = hclge_dbg_dump_mng_table,
	},
	{
		.cmd = HNAE3_DBG_CMD_LOOPBACK,
		.dbg_read_func = hclge_dbg_dump_loopback,
	},
	{
		.cmd = HNAE3_DBG_CMD_PTP_INFO,
		.dbg_read_func = hclge_dbg_dump_ptp_info,
	},
	{
		.cmd = HNAE3_DBG_CMD_INTERRUPT_INFO,
		.dbg_read_func = hclge_dbg_dump_interrupt,
	},
	{
		.cmd = HNAE3_DBG_CMD_RESET_INFO,
		.dbg_read_func = hclge_dbg_seq_dump_rst_info,
	},
	{
		.cmd = HNAE3_DBG_CMD_IMP_INFO,
		.dbg_read_func = hclge_dbg_get_imp_stats_info,
	},
	{
		.cmd = HNAE3_DBG_CMD_NCL_CONFIG,
		.dbg_read_func = hclge_dbg_dump_ncl_config,
	},
	{
		.cmd = HNAE3_DBG_CMD_REG_BIOS_COMMON,
		.dbg_read_func = hclge_dbg_dump_bios_reg_cmd,
	},
	{
		.cmd = HNAE3_DBG_CMD_REG_SSU,
		.dbg_read_func = hclge_dbg_dump_ssu_reg_cmd,
	},
	{
		.cmd = HNAE3_DBG_CMD_REG_IGU_EGU,
		.dbg_read_func = hclge_dbg_dump_igu_egu_reg_cmd,
	},
	{
		.cmd = HNAE3_DBG_CMD_REG_RPU,
		.dbg_read_func = hclge_dbg_dump_rpu_reg_cmd,
	},
	{
		.cmd = HNAE3_DBG_CMD_REG_NCSI,
		.dbg_read_func = hclge_dbg_dump_ncsi_reg_cmd,
	},
	{
		.cmd = HNAE3_DBG_CMD_REG_RTC,
		.dbg_read_func = hclge_dbg_dump_rtc_reg_cmd,
	},
	{
		.cmd = HNAE3_DBG_CMD_REG_PPP,
		.dbg_read_func = hclge_dbg_dump_ppp_reg_cmd,
	},
	{
		.cmd = HNAE3_DBG_CMD_REG_RCB,
		.dbg_read_func = hclge_dbg_dump_rcb_reg_cmd,
	},
	{
		.cmd = HNAE3_DBG_CMD_REG_TQP,
		.dbg_read_func = hclge_dbg_dump_tqp_reg_cmd,
	},
	{
		.cmd = HNAE3_DBG_CMD_REG_MAC,
		.dbg_read_func = hclge_dbg_dump_mac,
	},
	{
		.cmd = HNAE3_DBG_CMD_REG_DCB,
		.dbg_read_func = hclge_dbg_dump_dcb,
	},
	{
		.cmd = HNAE3_DBG_CMD_FD_TCAM,
		.dbg_read_func = hclge_dbg_dump_fd_tcam,
	},
	{
		.cmd = HNAE3_DBG_CMD_MAC_TNL_STATUS,
		.dbg_read_func = hclge_dbg_dump_mac_tnl_status,
	},
	{
		.cmd = HNAE3_DBG_CMD_SERV_INFO,
		.dbg_read_func = hclge_dbg_dump_serv_info,
	},
	{
		.cmd = HNAE3_DBG_CMD_VLAN_CONFIG,
		.dbg_read_func = hclge_dbg_dump_vlan_config,
	},
	{
		.cmd = HNAE3_DBG_CMD_FD_COUNTER,
		.dbg_read_func = hclge_dbg_dump_fd_counter,
	},
	{
		.cmd = HNAE3_DBG_CMD_UMV_INFO,
		.dbg_read_func = hclge_dbg_dump_umv_info,
	},
};

int hclge_dbg_get_read_func(struct hnae3_handle *handle, enum hnae3_dbg_cmd cmd,
			    read_func *func)
{
	struct hclge_vport *vport = hclge_get_vport(handle);
	const struct hclge_dbg_func *cmd_func;
	struct hclge_dev *hdev = vport->back;
	u32 i;

	for (i = 0; i < ARRAY_SIZE(hclge_dbg_cmd_func); i++) {
		if (cmd == hclge_dbg_cmd_func[i].cmd) {
			cmd_func = &hclge_dbg_cmd_func[i];
			*func = cmd_func->dbg_read_func;
			return 0;
		}
	}

	dev_err(&hdev->pdev->dev, "invalid command(%d)\n", cmd);
	return -EINVAL;
}
