

/*
 * Copyright 2021-present Infosys Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */
 
/**************************************
 * s1InterMmeHandoverStates.cpp
 * This is an auto generated file.
 * Please do not edit this file.
 * All edits to be made through template source file
 * <TOP-DIR/scripts/SMCodeGen/templates/stateMachineTmpls/state.cpp.tt>
 **************************************/


#include "actionTable.h"
#include "actionHandlers/actionHandlers.h"
#include <mmeSmDefs.h>
#include <utils/mmeStatesUtils.h>
#include <utils/mmeTimerTypes.h>

#include "mmeStates/s1InterMmeHandoverStates.h"

using namespace mme;
using namespace SM;


/******************************************************************************
* Constructor
******************************************************************************/
InterS1HoStartSrcMme::InterS1HoStartSrcMme():State()
{
        stateEntryAction = &MmeStatesUtils::on_state_entry;
        stateExitAction = &MmeStatesUtils::on_state_exit;
        eventValidator = &MmeStatesUtils::validate_event;
		
}

/******************************************************************************
* Destructor
******************************************************************************/
InterS1HoStartSrcMme::~InterS1HoStartSrcMme()
{
}

/******************************************************************************
* creates and returns static instance
******************************************************************************/
InterS1HoStartSrcMme* InterS1HoStartSrcMme::Instance()
{
        static InterS1HoStartSrcMme state;
        return &state;
}

/******************************************************************************
* initializes eventToActionsMap
******************************************************************************/
void InterS1HoStartSrcMme::initialize()
{
        {
                ActionTable actionTable;
                actionTable.addAction(&ActionHandlers::send_fr_request_to_target_mme);
                actionTable.setNextState(S1FrWfHoRequestRes::Instance());
                eventToActionsMap[INTER_S1HO_START] = actionTable;
        }
}

/******************************************************************************
* returns stateId
******************************************************************************/
uint16_t InterS1HoStartSrcMme::getStateId()const
{
	return inter_s1_ho_start_src_mme;
}

/******************************************************************************
* returns stateName
******************************************************************************/
const char* InterS1HoStartSrcMme::getStateName()const
{
	return "inter_s1_ho_start_src_mme";
}

/******************************************************************************
* Constructor
******************************************************************************/
S1FrWfHoRequestRes::S1FrWfHoRequestRes():State()
{
        stateEntryAction = &MmeStatesUtils::on_state_entry;
        stateExitAction = &MmeStatesUtils::on_state_exit;
        eventValidator = &MmeStatesUtils::validate_event;
		
}

/******************************************************************************
* Destructor
******************************************************************************/
S1FrWfHoRequestRes::~S1FrWfHoRequestRes()
{
}

/******************************************************************************
* creates and returns static instance
******************************************************************************/
S1FrWfHoRequestRes* S1FrWfHoRequestRes::Instance()
{
        static S1FrWfHoRequestRes state;
        return &state;
}

/******************************************************************************
* initializes eventToActionsMap
******************************************************************************/
void S1FrWfHoRequestRes::initialize()
{
        {
                ActionTable actionTable;
                actionTable.addAction(&ActionHandlers::process_fr_res);
                actionTable.addAction(&ActionHandlers::send_ho_command_to_src_enb);
                actionTable.setNextState(S1HoWfEnbStatusTransfer::Instance());
                eventToActionsMap[FWD_RELOCATION_RES_RCVD] = actionTable;
        }
}

/******************************************************************************
* returns stateId
******************************************************************************/
uint16_t S1FrWfHoRequestRes::getStateId()const
{
	return s1_fr_wf_ho_request_res;
}

/******************************************************************************
* returns stateName
******************************************************************************/
const char* S1FrWfHoRequestRes::getStateName()const
{
	return "s1_fr_wf_ho_request_res";
}

/******************************************************************************
* Constructor
******************************************************************************/
S1HoWfEnbStatusTransfer::S1HoWfEnbStatusTransfer():State()
{
        stateEntryAction = &MmeStatesUtils::on_state_entry;
        stateExitAction = &MmeStatesUtils::on_state_exit;
        eventValidator = &MmeStatesUtils::validate_event;
		
}

/******************************************************************************
* Destructor
******************************************************************************/
S1HoWfEnbStatusTransfer::~S1HoWfEnbStatusTransfer()
{
}

/******************************************************************************
* creates and returns static instance
******************************************************************************/
S1HoWfEnbStatusTransfer* S1HoWfEnbStatusTransfer::Instance()
{
        static S1HoWfEnbStatusTransfer state;
        return &state;
}

/******************************************************************************
* initializes eventToActionsMap
******************************************************************************/
void S1HoWfEnbStatusTransfer::initialize()
{
        {
                ActionTable actionTable;
                actionTable.addAction(&ActionHandlers::send_fwd_acc_ctxt_noti_to_target_mme);
                actionTable.setNextState(S1HoWfFwdAccCtxtAck::Instance());
                eventToActionsMap[ENB_STATUS_TRANSFER_RECV_FROM_ENB] = actionTable;
        }
}

/******************************************************************************
* returns stateId
******************************************************************************/
uint16_t S1HoWfEnbStatusTransfer::getStateId()const
{
	return s1_ho_wf_enb_status_transfer;
}

/******************************************************************************
* returns stateName
******************************************************************************/
const char* S1HoWfEnbStatusTransfer::getStateName()const
{
	return "s1_ho_wf_enb_status_transfer";
}

/******************************************************************************
* Constructor
******************************************************************************/
S1HoWfFwdAccCtxtAck::S1HoWfFwdAccCtxtAck():State()
{
        stateEntryAction = &MmeStatesUtils::on_state_entry;
        stateExitAction = &MmeStatesUtils::on_state_exit;
        eventValidator = &MmeStatesUtils::validate_event;
		
}

/******************************************************************************
* Destructor
******************************************************************************/
S1HoWfFwdAccCtxtAck::~S1HoWfFwdAccCtxtAck()
{
}

/******************************************************************************
* creates and returns static instance
******************************************************************************/
S1HoWfFwdAccCtxtAck* S1HoWfFwdAccCtxtAck::Instance()
{
        static S1HoWfFwdAccCtxtAck state;
        return &state;
}

/******************************************************************************
* initializes eventToActionsMap
******************************************************************************/
void S1HoWfFwdAccCtxtAck::initialize()
{
        {
                ActionTable actionTable;
                actionTable.addAction(&ActionHandlers::process_fwd_acc_ctxt_ack);
                actionTable.setNextState(S1HoWfFwdRelComp::Instance());
                eventToActionsMap[FWD_ACC_CTXT_ACK_RCVD] = actionTable;
        }
}

/******************************************************************************
* returns stateId
******************************************************************************/
uint16_t S1HoWfFwdAccCtxtAck::getStateId()const
{
	return s1_ho_wf_fwd_acc_ctxt_ack;
}

/******************************************************************************
* returns stateName
******************************************************************************/
const char* S1HoWfFwdAccCtxtAck::getStateName()const
{
	return "s1_ho_wf_fwd_acc_ctxt_ack";
}

/******************************************************************************
* Constructor
******************************************************************************/
S1HoWfFwdRelComp::S1HoWfFwdRelComp():State()
{
        stateEntryAction = &MmeStatesUtils::on_state_entry;
        stateExitAction = &MmeStatesUtils::on_state_exit;
        eventValidator = &MmeStatesUtils::validate_event;
		
}

/******************************************************************************
* Destructor
******************************************************************************/
S1HoWfFwdRelComp::~S1HoWfFwdRelComp()
{
}

/******************************************************************************
* creates and returns static instance
******************************************************************************/
S1HoWfFwdRelComp* S1HoWfFwdRelComp::Instance()
{
        static S1HoWfFwdRelComp state;
        return &state;
}

/******************************************************************************
* initializes eventToActionsMap
******************************************************************************/
void S1HoWfFwdRelComp::initialize()
{
        {
                ActionTable actionTable;
                actionTable.addAction(&ActionHandlers::send_fwd_rel_comp_ack_to_target_mme);
                actionTable.addAction(&ActionHandlers::send_s1_rel_cmd_to_ue_for_ho);
                eventToActionsMap[FWD_REL_COMP_NOTIFY_RCVD_FROM_TGT_MME] = actionTable;
        }
}

/******************************************************************************
* returns stateId
******************************************************************************/
uint16_t S1HoWfFwdRelComp::getStateId()const
{
	return s1_ho_wf_fwd_rel_comp;
}

/******************************************************************************
* returns stateName
******************************************************************************/
const char* S1HoWfFwdRelComp::getStateName()const
{
	return "s1_ho_wf_fwd_rel_comp";
}

/******************************************************************************
* Constructor
******************************************************************************/
InterS1HoStartTgtMme::InterS1HoStartTgtMme():State()
{
        stateEntryAction = &MmeStatesUtils::on_state_entry;
        stateExitAction = &MmeStatesUtils::on_state_exit;
        eventValidator = &MmeStatesUtils::validate_event;
		
}

/******************************************************************************
* Destructor
******************************************************************************/
InterS1HoStartTgtMme::~InterS1HoStartTgtMme()
{
}

/******************************************************************************
* creates and returns static instance
******************************************************************************/
InterS1HoStartTgtMme* InterS1HoStartTgtMme::Instance()
{
        static InterS1HoStartTgtMme state;
        return &state;
}

/******************************************************************************
* initializes eventToActionsMap
******************************************************************************/
void InterS1HoStartTgtMme::initialize()
{
        {
                ActionTable actionTable;
                actionTable.addAction(&ActionHandlers::send_ho_req_to_target_enb);
                actionTable.setNextState(S1HoWfHoReqAck::Instance());
                eventToActionsMap[HO_REQ_TO_TARGET_ENB] = actionTable;
        }
}

/******************************************************************************
* returns stateId
******************************************************************************/
uint16_t InterS1HoStartTgtMme::getStateId()const
{
	return inter_s1_ho_start_tgt_mme;
}

/******************************************************************************
* returns stateName
******************************************************************************/
const char* InterS1HoStartTgtMme::getStateName()const
{
	return "inter_s1_ho_start_tgt_mme";
}

/******************************************************************************
* Constructor
******************************************************************************/
S1HoWfHoReqAck::S1HoWfHoReqAck():State()
{
        stateEntryAction = &MmeStatesUtils::on_state_entry;
        stateExitAction = &MmeStatesUtils::on_state_exit;
        eventValidator = &MmeStatesUtils::validate_event;
		
}

/******************************************************************************
* Destructor
******************************************************************************/
S1HoWfHoReqAck::~S1HoWfHoReqAck()
{
}

/******************************************************************************
* creates and returns static instance
******************************************************************************/
S1HoWfHoReqAck* S1HoWfHoReqAck::Instance()
{
        static S1HoWfHoReqAck state;
        return &state;
}

/******************************************************************************
* initializes eventToActionsMap
******************************************************************************/
void S1HoWfHoReqAck::initialize()
{
        {
                ActionTable actionTable;
                actionTable.addAction(&ActionHandlers::process_ho_req_ack);
                actionTable.addAction(&ActionHandlers::send_fwd_rel_resp_to_src_mme);
                actionTable.setNextState(S1HoWfHoFwdAccCntxNoti::Instance());
                eventToActionsMap[HO_REQ_ACK_FROM_TARGET_ENB] = actionTable;
        }
}

/******************************************************************************
* returns stateId
******************************************************************************/
uint16_t S1HoWfHoReqAck::getStateId()const
{
	return s1_ho_wf_ho_req_ack;
}

/******************************************************************************
* returns stateName
******************************************************************************/
const char* S1HoWfHoReqAck::getStateName()const
{
	return "s1_ho_wf_ho_req_ack";
}

/******************************************************************************
* Constructor
******************************************************************************/
S1HoWfHoFwdAccCntxNoti::S1HoWfHoFwdAccCntxNoti():State()
{
        stateEntryAction = &MmeStatesUtils::on_state_entry;
        stateExitAction = &MmeStatesUtils::on_state_exit;
        eventValidator = &MmeStatesUtils::validate_event;
		
}

/******************************************************************************
* Destructor
******************************************************************************/
S1HoWfHoFwdAccCntxNoti::~S1HoWfHoFwdAccCntxNoti()
{
}

/******************************************************************************
* creates and returns static instance
******************************************************************************/
S1HoWfHoFwdAccCntxNoti* S1HoWfHoFwdAccCntxNoti::Instance()
{
        static S1HoWfHoFwdAccCntxNoti state;
        return &state;
}

/******************************************************************************
* initializes eventToActionsMap
******************************************************************************/
void S1HoWfHoFwdAccCntxNoti::initialize()
{
        {
                ActionTable actionTable;
                actionTable.addAction(&ActionHandlers::send_ho_fwd_acc_cntx_ack_to_src_mme);
                actionTable.addAction(&ActionHandlers::send_from_target_mme_status_tranfer_to_target_enb);
                actionTable.setNextState(S1HoWfHoNotifyFromTargetEnb::Instance());
                eventToActionsMap[HO_FWD_ACC_CNTX_NOTI] = actionTable;
        }
}

/******************************************************************************
* returns stateId
******************************************************************************/
uint16_t S1HoWfHoFwdAccCntxNoti::getStateId()const
{
	return s1_ho_wf_ho_fwd_acc_cntx_noti;
}

/******************************************************************************
* returns stateName
******************************************************************************/
const char* S1HoWfHoFwdAccCntxNoti::getStateName()const
{
	return "s1_ho_wf_ho_fwd_acc_cntx_noti";
}

/******************************************************************************
* Constructor
******************************************************************************/
S1HoWfHoNotifyFromTargetEnb::S1HoWfHoNotifyFromTargetEnb():State()
{
        stateEntryAction = &MmeStatesUtils::on_state_entry;
        stateExitAction = &MmeStatesUtils::on_state_exit;
        eventValidator = &MmeStatesUtils::validate_event;
		
}

/******************************************************************************
* Destructor
******************************************************************************/
S1HoWfHoNotifyFromTargetEnb::~S1HoWfHoNotifyFromTargetEnb()
{
}

/******************************************************************************
* creates and returns static instance
******************************************************************************/
S1HoWfHoNotifyFromTargetEnb* S1HoWfHoNotifyFromTargetEnb::Instance()
{
        static S1HoWfHoNotifyFromTargetEnb state;
        return &state;
}

/******************************************************************************
* initializes eventToActionsMap
******************************************************************************/
void S1HoWfHoNotifyFromTargetEnb::initialize()
{
        {
                ActionTable actionTable;
                actionTable.addAction(&ActionHandlers::process_s1_ho_notify_from_target_enb);
                actionTable.addAction(&ActionHandlers::send_ho_mb_req_to_sgw);
                actionTable.setNextState(S1HoWfMbRespFromSgw::Instance());
                eventToActionsMap[S1_HO_NOTIFY_FROM_TARGET_ENB] = actionTable;
        }
}

/******************************************************************************
* returns stateId
******************************************************************************/
uint16_t S1HoWfHoNotifyFromTargetEnb::getStateId()const
{
	return s1_ho_wf_ho_notify_from_target_enb;
}

/******************************************************************************
* returns stateName
******************************************************************************/
const char* S1HoWfHoNotifyFromTargetEnb::getStateName()const
{
	return "s1_ho_wf_ho_notify_from_target_enb";
}

/******************************************************************************
* Constructor
******************************************************************************/
S1HoWfMbRespFromSgw::S1HoWfMbRespFromSgw():State()
{
        stateEntryAction = &MmeStatesUtils::on_state_entry;
        stateExitAction = &MmeStatesUtils::on_state_exit;
        eventValidator = &MmeStatesUtils::validate_event;
		
}

/******************************************************************************
* Destructor
******************************************************************************/
S1HoWfMbRespFromSgw::~S1HoWfMbRespFromSgw()
{
}

/******************************************************************************
* creates and returns static instance
******************************************************************************/
S1HoWfMbRespFromSgw* S1HoWfMbRespFromSgw::Instance()
{
        static S1HoWfMbRespFromSgw state;
        return &state;
}

/******************************************************************************
* initializes eventToActionsMap
******************************************************************************/
void S1HoWfMbRespFromSgw::initialize()
{
        {
                ActionTable actionTable;
                actionTable.addAction(&ActionHandlers::process_mb_resp_from_sgw);
                actionTable.addAction(&ActionHandlers::send_ho_fwd_rel_comp_notification_to_src_mme);
                actionTable.setNextState(S1HoWfMbRespFromSgw::Instance());
                eventToActionsMap[MB_RESP_FROM_SGW] = actionTable;
        }
}

/******************************************************************************
* returns stateId
******************************************************************************/
uint16_t S1HoWfMbRespFromSgw::getStateId()const
{
	return s1_ho_wf_mb_resp_from_sgw;
}

/******************************************************************************
* returns stateName
******************************************************************************/
const char* S1HoWfMbRespFromSgw::getStateName()const
{
	return "s1_ho_wf_mb_resp_from_sgw";
}
