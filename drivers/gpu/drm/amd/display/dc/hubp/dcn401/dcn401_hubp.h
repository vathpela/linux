/*
 * Copyright 2023 Advanced Micro Devices, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors: AMD
 *
 */

#ifndef __DC_HUBP_DCN401_H__
#define __DC_HUBP_DCN401_H__

#include "dcn20/dcn20_hubp.h"
#include "dcn21/dcn21_hubp.h"
#include "dcn30/dcn30_hubp.h"
#include "dcn31/dcn31_hubp.h"
#include "dcn32/dcn32_hubp.h"
#include "dml2/dml21/inc/dml_top_dchub_registers.h"

#define HUBP_3DLUT_FL_REG_LIST_DCN401(inst)\
	SRI_ARR_US(_3DLUT_FL_CONFIG, HUBP, inst),\
	SRI_ARR_US(_3DLUT_FL_BIAS_SCALE, HUBP, inst),\
	SRI_ARR(HUBP_3DLUT_ADDRESS_HIGH, CURSOR0_, inst),\
	SRI_ARR(HUBP_3DLUT_ADDRESS_LOW, CURSOR0_, inst),\
	SRI_ARR(HUBP_3DLUT_CONTROL, CURSOR0_, inst),\
	SRI_ARR(HUBP_3DLUT_DLG_PARAM, CURSOR0_, inst)

#define HUBP_MASK_SH_LIST_DCN401(mask_sh)\
	HUBP_SF(HUBPREQ0_DCN_DMDATA_VM_CNTL, REFCYC_PER_VM_DMDATA, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_DMDATA_VM_CNTL, DMDATA_VM_FAULT_STATUS, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_DMDATA_VM_CNTL, DMDATA_VM_FAULT_STATUS_CLEAR, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_DMDATA_VM_CNTL, DMDATA_VM_UNDERFLOW_STATUS, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_DMDATA_VM_CNTL, DMDATA_VM_LATE_STATUS, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_DMDATA_VM_CNTL, DMDATA_VM_UNDERFLOW_STATUS_CLEAR, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_DMDATA_VM_CNTL, DMDATA_VM_DONE, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_CNTL, HUBP_BLANK_EN, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_CNTL, HUBP_TTU_DISABLE, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_CNTL, HUBP_UNDERFLOW_STATUS, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_CNTL, HUBP_UNDERFLOW_CLEAR, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_CNTL, HUBP_NO_OUTSTANDING_REQ, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_CNTL, HUBP_VTG_SEL, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_CNTL, HUBP_UNBOUNDED_REQ_MODE, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_CNTL, HUBP_IN_BLANK, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_CNTL, HUBP_SOFT_RESET, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_ADDR_CONFIG, NUM_PIPES, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_ADDR_CONFIG, PIPE_INTERLEAVE, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_ADDR_CONFIG, MAX_COMPRESSED_FRAGS, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_ADDR_CONFIG, NUM_PKRS, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_TILING_CONFIG, SW_MODE, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_PITCH, PITCH, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_PITCH_C, PITCH_C, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_SURFACE_CONFIG, SURFACE_PIXEL_FORMAT, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_FLIP_CONTROL, SURFACE_FLIP_TYPE, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_FLIP_CONTROL, SURFACE_FLIP_MODE_FOR_STEREOSYNC, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_FLIP_CONTROL, SURFACE_FLIP_IN_STEREOSYNC, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_FLIP_CONTROL, SURFACE_FLIP_PENDING, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_FLIP_CONTROL, SURFACE_UPDATE_LOCK, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_PRI_VIEWPORT_DIMENSION, PRI_VIEWPORT_WIDTH, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_PRI_VIEWPORT_DIMENSION, PRI_VIEWPORT_HEIGHT, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_PRI_VIEWPORT_START, PRI_VIEWPORT_X_START, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_PRI_VIEWPORT_START, PRI_VIEWPORT_Y_START, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_SEC_VIEWPORT_DIMENSION, SEC_VIEWPORT_WIDTH, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_SEC_VIEWPORT_DIMENSION, SEC_VIEWPORT_HEIGHT, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_SEC_VIEWPORT_START, SEC_VIEWPORT_X_START, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_SEC_VIEWPORT_START, SEC_VIEWPORT_Y_START, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_PRI_VIEWPORT_DIMENSION_C, PRI_VIEWPORT_WIDTH_C, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_PRI_VIEWPORT_DIMENSION_C, PRI_VIEWPORT_HEIGHT_C, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_PRI_VIEWPORT_START_C, PRI_VIEWPORT_X_START_C, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_PRI_VIEWPORT_START_C, PRI_VIEWPORT_Y_START_C, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_SEC_VIEWPORT_DIMENSION_C, SEC_VIEWPORT_WIDTH_C, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_SEC_VIEWPORT_DIMENSION_C, SEC_VIEWPORT_HEIGHT_C, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_SEC_VIEWPORT_START_C, SEC_VIEWPORT_X_START_C, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_SEC_VIEWPORT_START_C, SEC_VIEWPORT_Y_START_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_PRIMARY_SURFACE_ADDRESS_HIGH, PRIMARY_SURFACE_ADDRESS_HIGH, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_PRIMARY_SURFACE_ADDRESS, PRIMARY_SURFACE_ADDRESS, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SECONDARY_SURFACE_ADDRESS_HIGH, SECONDARY_SURFACE_ADDRESS_HIGH, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SECONDARY_SURFACE_ADDRESS, SECONDARY_SURFACE_ADDRESS, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_PRIMARY_SURFACE_ADDRESS_HIGH_C, PRIMARY_SURFACE_ADDRESS_HIGH_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_PRIMARY_SURFACE_ADDRESS_C, PRIMARY_SURFACE_ADDRESS_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SECONDARY_SURFACE_ADDRESS_HIGH_C, SECONDARY_SURFACE_ADDRESS_HIGH_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SECONDARY_SURFACE_ADDRESS_C, SECONDARY_SURFACE_ADDRESS_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_INUSE, SURFACE_INUSE_ADDRESS, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_INUSE_HIGH, SURFACE_INUSE_ADDRESS_HIGH, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_INUSE_C, SURFACE_INUSE_ADDRESS_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_INUSE_HIGH_C, SURFACE_INUSE_ADDRESS_HIGH_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_EARLIEST_INUSE, SURFACE_EARLIEST_INUSE_ADDRESS, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_EARLIEST_INUSE_HIGH, SURFACE_EARLIEST_INUSE_ADDRESS_HIGH, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_EARLIEST_INUSE_C, SURFACE_EARLIEST_INUSE_ADDRESS_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_EARLIEST_INUSE_HIGH_C, SURFACE_EARLIEST_INUSE_ADDRESS_HIGH_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_CONTROL, PRIMARY_SURFACE_TMZ, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_CONTROL, PRIMARY_SURFACE_TMZ_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_CONTROL, PRIMARY_SURFACE_DCC_EN, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_CONTROL, SECONDARY_SURFACE_TMZ, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_CONTROL, SECONDARY_SURFACE_TMZ_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_CONTROL, SECONDARY_SURFACE_DCC_EN, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_SURFACE_FLIP_INTERRUPT, SURFACE_FLIP_INT_MASK, mask_sh),\
	HUBP_SF(HUBPRET0_HUBPRET_CONTROL, DET_BUF_PLANE1_BASE_ADDRESS, mask_sh),\
	HUBP_SF(HUBPRET0_HUBPRET_CONTROL, CROSSBAR_SRC_CB_B, mask_sh),\
	HUBP_SF(HUBPRET0_HUBPRET_CONTROL, CROSSBAR_SRC_CR_R, mask_sh),\
	HUBP_SF(HUBPRET0_HUBPRET_CONTROL, CROSSBAR_SRC_Y_G, mask_sh),\
	HUBP_SF(HUBPRET0_HUBPRET_CONTROL, CROSSBAR_SRC_ALPHA, mask_sh),\
	HUBP_SF(HUBPRET0_HUBPRET_CONTROL, PACK_3TO2_ELEMENT_DISABLE, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_EXPANSION_MODE, DRQ_EXPANSION_MODE, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_EXPANSION_MODE, PRQ_EXPANSION_MODE, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_EXPANSION_MODE, MRQ_EXPANSION_MODE, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_EXPANSION_MODE, CRQ_EXPANSION_MODE, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_REQ_SIZE_CONFIG, CHUNK_SIZE, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_REQ_SIZE_CONFIG, MIN_CHUNK_SIZE, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_REQ_SIZE_CONFIG, DPTE_GROUP_SIZE, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_REQ_SIZE_CONFIG, SWATH_HEIGHT, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_REQ_SIZE_CONFIG, PTE_ROW_HEIGHT_LINEAR, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_REQ_SIZE_CONFIG_C, CHUNK_SIZE_C, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_REQ_SIZE_CONFIG_C, MIN_CHUNK_SIZE_C, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_REQ_SIZE_CONFIG_C, DPTE_GROUP_SIZE_C, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_REQ_SIZE_CONFIG_C, SWATH_HEIGHT_C, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_REQ_SIZE_CONFIG_C, PTE_ROW_HEIGHT_LINEAR_C, mask_sh),\
	HUBP_SF(HUBPREQ0_BLANK_OFFSET_0, REFCYC_H_BLANK_END, mask_sh),\
	HUBP_SF(HUBPREQ0_BLANK_OFFSET_0, DLG_V_BLANK_END, mask_sh),\
	HUBP_SF(HUBPREQ0_BLANK_OFFSET_1, MIN_DST_Y_NEXT_START, mask_sh),\
	HUBP_SF(HUBPREQ0_DST_DIMENSIONS, REFCYC_PER_HTOTAL, mask_sh),\
	HUBP_SF(HUBPREQ0_DST_AFTER_SCALER, REFCYC_X_AFTER_SCALER, mask_sh),\
	HUBP_SF(HUBPREQ0_DST_AFTER_SCALER, DST_Y_AFTER_SCALER, mask_sh),\
	HUBP_SF(HUBPREQ0_VBLANK_PARAMETERS_0, DST_Y_PER_VM_VBLANK, mask_sh),\
	HUBP_SF(HUBPREQ0_VBLANK_PARAMETERS_0, DST_Y_PER_ROW_VBLANK, mask_sh),\
	HUBP_SF(HUBPREQ0_REF_FREQ_TO_PIX_FREQ, REF_FREQ_TO_PIX_FREQ, mask_sh),\
	HUBP_SF(HUBPREQ0_VBLANK_PARAMETERS_1, REFCYC_PER_PTE_GROUP_VBLANK_L, mask_sh),\
	HUBP_SF(HUBPREQ0_VBLANK_PARAMETERS_3, REFCYC_PER_META_CHUNK_VBLANK_L, mask_sh),\
	HUBP_SF(HUBPREQ0_NOM_PARAMETERS_4, DST_Y_PER_META_ROW_NOM_L, mask_sh),\
	HUBP_SF(HUBPREQ0_NOM_PARAMETERS_5, REFCYC_PER_META_CHUNK_NOM_L, mask_sh),\
	HUBP_SF(HUBPREQ0_PER_LINE_DELIVERY_PRE, REFCYC_PER_LINE_DELIVERY_PRE_L, mask_sh),\
	HUBP_SF(HUBPREQ0_PER_LINE_DELIVERY_PRE, REFCYC_PER_LINE_DELIVERY_PRE_C, mask_sh),\
	HUBP_SF(HUBPREQ0_PER_LINE_DELIVERY, REFCYC_PER_LINE_DELIVERY_L, mask_sh),\
	HUBP_SF(HUBPREQ0_PER_LINE_DELIVERY, REFCYC_PER_LINE_DELIVERY_C, mask_sh),\
	HUBP_SF(HUBPREQ0_VBLANK_PARAMETERS_2, REFCYC_PER_PTE_GROUP_VBLANK_C, mask_sh),\
	HUBP_SF(HUBPREQ0_VBLANK_PARAMETERS_4, REFCYC_PER_META_CHUNK_VBLANK_C, mask_sh),\
	HUBP_SF(HUBPREQ0_NOM_PARAMETERS_6, DST_Y_PER_META_ROW_NOM_C, mask_sh),\
	HUBP_SF(HUBPREQ0_NOM_PARAMETERS_7, REFCYC_PER_META_CHUNK_NOM_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_TTU_QOS_WM, QoS_LEVEL_LOW_WM, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_TTU_QOS_WM, QoS_LEVEL_HIGH_WM, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_GLOBAL_TTU_CNTL, MIN_TTU_VBLANK, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_GLOBAL_TTU_CNTL, QoS_LEVEL_FLIP, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_GLOBAL_TTU_CNTL, ROW_TTU_MODE, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_SURF0_TTU_CNTL0, REFCYC_PER_REQ_DELIVERY, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_SURF0_TTU_CNTL0, QoS_LEVEL_FIXED, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_SURF0_TTU_CNTL0, QoS_RAMP_DISABLE, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_SURF0_TTU_CNTL1, REFCYC_PER_REQ_DELIVERY_PRE, mask_sh),\
	HUBP_SF(HUBP0_HUBP_CLK_CNTL, HUBP_CLOCK_ENABLE, mask_sh),\
	HUBP_MASK_SH_LIST_DCN_VM(mask_sh),\
	HUBP_SF(HUBP0_DCSURF_SURFACE_CONFIG, ROTATION_ANGLE, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_SURFACE_CONFIG, H_MIRROR_EN, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_SURFACE_CONFIG, ALPHA_PLANE_EN, mask_sh),\
	HUBP_SF(HUBPREQ0_PREFETCH_SETTINGS, DST_Y_PREFETCH, mask_sh),\
	HUBP_SF(HUBPREQ0_PREFETCH_SETTINGS, VRATIO_PREFETCH, mask_sh),\
	HUBP_SF(HUBPREQ0_PREFETCH_SETTINGS_C, VRATIO_PREFETCH_C, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_VM_SYSTEM_APERTURE_LOW_ADDR, MC_VM_SYSTEM_APERTURE_LOW_ADDR, mask_sh),\
	HUBP_SF(HUBPREQ0_DCN_VM_SYSTEM_APERTURE_HIGH_ADDR, MC_VM_SYSTEM_APERTURE_HIGH_ADDR, mask_sh),\
	HUBP_SF(HUBPREQ0_CURSOR_SETTINGS, CURSOR0_DST_Y_OFFSET, mask_sh), \
	HUBP_SF(HUBPREQ0_CURSOR_SETTINGS, CURSOR0_CHUNK_HDL_ADJUST, mask_sh), \
	HUBP_SF(CURSOR0_0_CURSOR_SURFACE_ADDRESS_HIGH, CURSOR_SURFACE_ADDRESS_HIGH, mask_sh), \
	HUBP_SF(CURSOR0_0_CURSOR_SURFACE_ADDRESS, CURSOR_SURFACE_ADDRESS, mask_sh), \
	HUBP_SF(CURSOR0_0_CURSOR_SIZE, CURSOR_WIDTH, mask_sh), \
	HUBP_SF(CURSOR0_0_CURSOR_SIZE, CURSOR_HEIGHT, mask_sh), \
	HUBP_SF(CURSOR0_0_CURSOR_CONTROL, CURSOR_MODE, mask_sh), \
	HUBP_SF(CURSOR0_0_CURSOR_CONTROL, CURSOR_REQ_MODE, mask_sh), \
	HUBP_SF(CURSOR0_0_CURSOR_CONTROL, CURSOR_2X_MAGNIFY, mask_sh), \
	HUBP_SF(CURSOR0_0_CURSOR_CONTROL, CURSOR_PITCH, mask_sh), \
	HUBP_SF(CURSOR0_0_CURSOR_CONTROL, CURSOR_LINES_PER_CHUNK, mask_sh), \
	HUBP_SF(CURSOR0_0_CURSOR_CONTROL, CURSOR_ENABLE, mask_sh), \
	HUBP_SF(CURSOR0_0_CURSOR_POSITION, CURSOR_X_POSITION, mask_sh), \
	HUBP_SF(CURSOR0_0_CURSOR_POSITION, CURSOR_Y_POSITION, mask_sh), \
	HUBP_SF(CURSOR0_0_CURSOR_HOT_SPOT, CURSOR_HOT_SPOT_X, mask_sh), \
	HUBP_SF(CURSOR0_0_CURSOR_HOT_SPOT, CURSOR_HOT_SPOT_Y, mask_sh), \
	HUBP_SF(CURSOR0_0_CURSOR_DST_OFFSET, CURSOR_DST_X_OFFSET, mask_sh), \
	HUBP_SF(CURSOR0_0_DMDATA_ADDRESS_HIGH, DMDATA_ADDRESS_HIGH, mask_sh), \
	HUBP_SF(CURSOR0_0_DMDATA_CNTL, DMDATA_MODE, mask_sh), \
	HUBP_SF(CURSOR0_0_DMDATA_CNTL, DMDATA_UPDATED, mask_sh), \
	HUBP_SF(CURSOR0_0_DMDATA_CNTL, DMDATA_REPEAT, mask_sh), \
	HUBP_SF(CURSOR0_0_DMDATA_CNTL, DMDATA_SIZE, mask_sh), \
	HUBP_SF(CURSOR0_0_DMDATA_SW_CNTL, DMDATA_SW_UPDATED, mask_sh), \
	HUBP_SF(CURSOR0_0_DMDATA_SW_CNTL, DMDATA_SW_REPEAT, mask_sh), \
	HUBP_SF(CURSOR0_0_DMDATA_SW_CNTL, DMDATA_SW_SIZE, mask_sh), \
	HUBP_SF(CURSOR0_0_DMDATA_QOS_CNTL, DMDATA_QOS_MODE, mask_sh), \
	HUBP_SF(CURSOR0_0_DMDATA_QOS_CNTL, DMDATA_QOS_LEVEL, mask_sh), \
	HUBP_SF(CURSOR0_0_DMDATA_QOS_CNTL, DMDATA_DL_DELTA, mask_sh), \
	HUBP_SF(CURSOR0_0_DMDATA_STATUS, DMDATA_DONE, mask_sh),\
	HUBP_SF(HUBPREQ0_FLIP_PARAMETERS_0, DST_Y_PER_VM_FLIP, mask_sh),\
	HUBP_SF(HUBPREQ0_FLIP_PARAMETERS_0, DST_Y_PER_ROW_FLIP, mask_sh),\
	HUBP_SF(HUBPREQ0_FLIP_PARAMETERS_1, REFCYC_PER_PTE_GROUP_FLIP_L, mask_sh),\
	HUBP_SF(HUBPREQ0_FLIP_PARAMETERS_2, REFCYC_PER_META_CHUNK_FLIP_L, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_CNTL, HUBP_VREADY_AT_OR_AFTER_VSYNC, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_CNTL, HUBP_DISABLE_STOP_DATA_DURING_VM, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_FLIP_CONTROL, HUBPREQ_MASTER_UPDATE_LOCK_STATUS, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_FLIP_CONTROL2, SURFACE_GSL_ENABLE, mask_sh),\
	HUBP_SF(HUBPREQ0_DCSURF_FLIP_CONTROL2, SURFACE_TRIPLE_BUFFER_ENABLE, mask_sh),\
	HUBP_SF(HUBPREQ0_VMID_SETTINGS_0, VMID, mask_sh),\
	HUBP_SF(HUBPREQ0_FLIP_PARAMETERS_3, REFCYC_PER_VM_GROUP_FLIP, mask_sh),\
	HUBP_SF(HUBPREQ0_FLIP_PARAMETERS_4, REFCYC_PER_VM_REQ_FLIP, mask_sh),\
	HUBP_SF(HUBPREQ0_FLIP_PARAMETERS_5, REFCYC_PER_PTE_GROUP_FLIP_C, mask_sh),\
	HUBP_SF(HUBPREQ0_FLIP_PARAMETERS_6, REFCYC_PER_META_CHUNK_FLIP_C, mask_sh),\
	HUBP_SF(HUBPREQ0_VBLANK_PARAMETERS_5, REFCYC_PER_VM_GROUP_VBLANK, mask_sh),\
	HUBP_SF(HUBPREQ0_VBLANK_PARAMETERS_6, REFCYC_PER_VM_REQ_VBLANK, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_REQ_SIZE_CONFIG, VM_GROUP_SIZE, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_MALL_CONFIG, USE_MALL_SEL, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_MALL_CONFIG, USE_MALL_FOR_CURSOR, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_VMPG_CONFIG, VMPG_SIZE, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_VMPG_CONFIG, PTE_BUFFER_MODE, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_VMPG_CONFIG, BIGK_FRAGMENT_SIZE, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_VMPG_CONFIG, FORCE_ONE_ROW_FOR_FRAME, mask_sh),\
	HUBP_SF(HUBPREQ0_UCLK_PSTATE_FORCE, DATA_UCLK_PSTATE_FORCE_EN, mask_sh),\
	HUBP_SF(HUBPREQ0_UCLK_PSTATE_FORCE, DATA_UCLK_PSTATE_FORCE_VALUE, mask_sh),\
	HUBP_SF(HUBPREQ0_UCLK_PSTATE_FORCE, CURSOR_UCLK_PSTATE_FORCE_EN, mask_sh),\
	HUBP_SF(HUBPREQ0_UCLK_PSTATE_FORCE, CURSOR_UCLK_PSTATE_FORCE_VALUE, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_MALL_CONFIG, MALL_PREF_CMD_TYPE, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_MALL_CONFIG, MALL_PREF_MODE, mask_sh),\
	HUBP_SF(HUBP0_3DLUT_FL_CONFIG, HUBP0_3DLUT_FL_MODE, mask_sh),\
	HUBP_SF(HUBP0_3DLUT_FL_CONFIG, HUBP0_3DLUT_FL_FORMAT, mask_sh),\
	HUBP_SF(HUBP0_3DLUT_FL_BIAS_SCALE, HUBP0_3DLUT_FL_BIAS, mask_sh),\
	HUBP_SF(HUBP0_3DLUT_FL_BIAS_SCALE, HUBP0_3DLUT_FL_SCALE, mask_sh),\
	HUBP_SF(CURSOR0_0_HUBP_3DLUT_CONTROL, HUBP_3DLUT_ENABLE, mask_sh),\
	HUBP_SF(CURSOR0_0_HUBP_3DLUT_CONTROL, HUBP_3DLUT_DONE, mask_sh),\
	HUBP_SF(CURSOR0_0_HUBP_3DLUT_CONTROL, HUBP_3DLUT_ADDRESSING_MODE, mask_sh),\
	HUBP_SF(CURSOR0_0_HUBP_3DLUT_CONTROL, HUBP_3DLUT_WIDTH, mask_sh),\
	HUBP_SF(CURSOR0_0_HUBP_3DLUT_CONTROL, HUBP_3DLUT_TMZ, mask_sh),\
	HUBP_SF(CURSOR0_0_HUBP_3DLUT_CONTROL, HUBP_3DLUT_CROSSBAR_SELECT_Y_G, mask_sh),\
	HUBP_SF(CURSOR0_0_HUBP_3DLUT_CONTROL, HUBP_3DLUT_CROSSBAR_SELECT_CB_B, mask_sh),\
	HUBP_SF(CURSOR0_0_HUBP_3DLUT_CONTROL, HUBP_3DLUT_CROSSBAR_SELECT_CR_R, mask_sh),\
	HUBP_SF(CURSOR0_0_HUBP_3DLUT_ADDRESS_HIGH, HUBP_3DLUT_ADDRESS_HIGH, mask_sh),\
	HUBP_SF(CURSOR0_0_HUBP_3DLUT_ADDRESS_LOW, HUBP_3DLUT_ADDRESS_LOW, mask_sh),\
	HUBP_SF(CURSOR0_0_HUBP_3DLUT_DLG_PARAM, REFCYC_PER_3DLUT_GROUP, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_VIEWPORT_MCACHE_SPLIT_COORDINATE, VIEWPORT_MCACHE_SPLIT_COORDINATE, mask_sh),\
	HUBP_SF(HUBP0_DCSURF_VIEWPORT_MCACHE_SPLIT_COORDINATE, VIEWPORT_MCACHE_SPLIT_COORDINATE_C, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_MCACHEID_CONFIG, MCACHEID_REG_READ_1H_P0, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_MCACHEID_CONFIG, MCACHEID_REG_READ_2H_P0, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_MCACHEID_CONFIG, MCACHEID_REG_READ_1H_P1, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_MCACHEID_CONFIG, MCACHEID_REG_READ_2H_P1, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_MCACHEID_CONFIG, MCACHEID_MALL_PREF_1H_P0, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_MCACHEID_CONFIG, MCACHEID_MALL_PREF_2H_P0, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_MCACHEID_CONFIG, MCACHEID_MALL_PREF_1H_P1, mask_sh),\
	HUBP_SF(HUBP0_DCHUBP_MCACHEID_CONFIG, MCACHEID_MALL_PREF_2H_P1, mask_sh)

void hubp401_update_mall_sel(struct hubp *hubp, uint32_t mall_sel, bool c_cursor);

void hubp401_setup(
		struct hubp *hubp,
	    struct dml2_dchub_per_pipe_register_set *pipe_regs,
		union dml2_global_sync_programming *pipe_global_sync,
		struct dc_crtc_timing *timing);

void hubp401_setup_interdependent(
		struct hubp *hubp,
		struct dml2_dchub_per_pipe_register_set *pipe_regs);

bool hubp401_program_surface_flip_and_addr(
	struct hubp *hubp,
	const struct dc_plane_address *address,
	bool flip_immediate);

void hubp401_dcc_control(struct hubp *hubp,
		struct dc_plane_dcc_param *dcc);

void hubp401_program_tiling(
	struct dcn20_hubp *hubp2,
	const struct dc_tiling_info *info,
	const enum surface_pixel_format pixel_format);

void hubp401_program_size(
	struct hubp *hubp,
	enum surface_pixel_format format,
	const struct plane_size *plane_size,
	struct dc_plane_dcc_param *dcc);

void hubp401_program_surface_config(
	struct hubp *hubp,
	enum surface_pixel_format format,
	struct dc_tiling_info *tiling_info,
	struct plane_size *plane_size,
	enum dc_rotation_angle rotation,
	struct dc_plane_dcc_param *dcc,
	bool horizontal_mirror,
	unsigned int compat_level);

void hubp401_set_viewport(struct hubp *hubp,
		const struct rect *viewport,
		const struct rect *viewport_c);
void hubp401_program_mcache_id_and_split_coordinate(
	struct hubp *hubp,
	struct dml2_hubp_pipe_mcache_regs *mcache_regs);
void hubp401_set_flip_int(struct hubp *hubp);

bool hubp401_in_blank(struct hubp *hubp);

void hubp401_cursor_set_position(
	struct hubp *hubp,
	const struct dc_cursor_position *pos,
	const struct dc_cursor_mi_param *param);

void hubp401_read_state(struct hubp *hubp);

bool hubp401_construct(
	struct dcn20_hubp *hubp2,
	struct dc_context *ctx,
	uint32_t inst,
	const struct dcn_hubp2_registers *hubp_regs,
	const struct dcn_hubp2_shift *hubp_shift,
	const struct dcn_hubp2_mask *hubp_mask);

void hubp401_init(struct hubp *hubp);

int hubp401_get_3dlut_fl_done(struct hubp *hubp);

void hubp401_set_unbounded_requesting(struct hubp *hubp, bool enable);

void hubp401_update_3dlut_fl_bias_scale(struct hubp *hubp, uint16_t bias, uint16_t scale);

void hubp401_program_3dlut_fl_crossbar(struct hubp *hubp,
	enum hubp_3dlut_fl_crossbar_bit_slice bit_slice_y_g,
	enum hubp_3dlut_fl_crossbar_bit_slice bit_slice_cb_b,
	enum hubp_3dlut_fl_crossbar_bit_slice bit_slice_cr_r);

void hubp401_program_3dlut_fl_tmz_protected(struct hubp *hubp, uint8_t protection_bits);

void hubp401_program_3dlut_fl_width(struct hubp *hubp, enum hubp_3dlut_fl_width width);

void hubp401_program_3dlut_fl_addressing_mode(struct hubp *hubp, enum hubp_3dlut_fl_addressing_mode addr_mode);

void hubp401_enable_3dlut_fl(struct hubp *hubp, bool enable);

void hubp401_program_3dlut_fl_dlg_param(struct hubp *hubp, int refcyc_per_3dlut_group);

void hubp401_program_3dlut_fl_addr(struct hubp *hubp, const struct dc_plane_address address);

void hubp401_program_3dlut_fl_format(struct hubp *hubp, enum hubp_3dlut_fl_format format);

void hubp401_program_3dlut_fl_mode(struct hubp *hubp, enum hubp_3dlut_fl_mode mode);

void hubp401_clear_tiling(struct hubp *hubp);

void hubp401_vready_at_or_After_vsync(struct hubp *hubp,
	union dml2_global_sync_programming *pipe_global_sync,
	struct dc_crtc_timing *timing);

void hubp401_program_requestor(
	struct hubp *hubp,
	struct dml2_display_rq_regs *rq_regs);

void hubp401_program_deadline(
	struct hubp *hubp,
	struct dml2_display_dlg_regs *dlg_attr,
	struct dml2_display_ttu_regs *ttu_attr);

#endif /* __DC_HUBP_DCN401_H__ */
