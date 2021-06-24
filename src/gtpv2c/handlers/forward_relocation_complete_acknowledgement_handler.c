/*
 * Copyright 2019-present Open Networking Foundation
 * Copyright (c) 2019, Infosys Ltd.
 * Copyright (c) 2003-2018, Great Software Laboratory Pvt. Ltd.
 * Copyright (c) 2017 Intel Corporation 
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>

#include "log.h"
#include "err_codes.h"
#include "ipc_api.h"
#include "msgType.h"

#include "gtpv2c_config.h"
#include <gtpV2StackWrappers.h>
#include "../../../include/gtpv2c/gtp.h"
#include "../../../include/gtpv2c/gtpv2c.h"
#include "../../../include/gtpv2c/gtpv2c_ie.h"
#include "../../gtpv2c/cpp_utils/gtp_cpp_wrapper.h"

#include "gtp.h"


/************************************************************************
Current file : Stage 5 handler.
ATTACH stages :
	Stage 1 : IAM-->[stage1 handler]-->AIR, ULR
	Stage 2 : AIA, ULA -->[stage2 handler]--> Auth req
	Stage 3 : Auth resp-->[stage3 handler]-->Sec mode cmd
	Stage 4 : sec mode resp-->[stage4 handler]-->esm infor req
-->	Stage 5 : esm infor resp-->[stage5 handler]-->create session
	Stage 6 : create session resp-->[stage6 handler]-->init ctx setup
	Stage 7 : attach complete-->[stage7 handler]-->modify bearer
**************************************************************************/

/****Globals and externs ***/

/*S11 CP communication parameters*/

extern int g_gtp_fd;
extern struct sockaddr_in g_s10_cp_addr;
extern socklen_t g_s10_serv_size;

extern gtpv2c_config_t g_gtp_cfg;

/****Global and externs end***/
struct CS_Q_msg *g_csReqInfo;

struct FR_Q_msg *g_frReqInfo;

extern struct GtpV2Stack* gtpStack_gp;

/**
* Stage specific message processing.
*/
static int
forward_relocation_complete_acknowledgement_processing(struct FWD_REL_CMP_ACK_Q_msg * g_frRelCmpAckInfo)
{
	struct MsgBuffer*  frRelCmpAckMsgBuf_p = createMsgBuffer(S10_MSGBUF_SIZE);
    if(frRelCmpAckMsgBuf_p == NULL)
    {
        log_msg(LOG_ERROR, "Error in initializing msg buffers required by gtp codec.");
        return -1;
    }
    struct sockaddr_in tmme_addr = {0};
    GtpV2MessageHeader gtpHeader;
	gtpHeader.msgType = GTP_FORWARD_RELOCATION_CMP_ACK;
    uint32_t seq = 0;
	get_sequence(&seq);
	gtpHeader.sequenceNumber = seq;
	gtpHeader.teidPresent = true;
	gtpHeader.teid = 0; // Need to check from 3gpp

	tmme_addr.sin_family = AF_INET;
	tmme_addr.sin_port = htons(g_gtp_cfg.egtp_def_port);

    if(g_frRelCmpAckInfo->target_mme_ip != 0) {
    	tmme_addr.sin_addr.s_addr = g_frRelCmpAckInfo->target_mme_ip;
    } else {
    	tmme_addr = g_s10_cp_addr;
    }

	log_msg(LOG_INFO,"In Forward Relocation Complete acknowledgement handler->ue_idx:%d",g_frRelCmpAckInfo->ue_idx);

    add_gtp_transaction(gtpHeader.sequenceNumber, 
                          g_frRelCmpAckInfo->ue_idx);

    ForwardRelocationCompleteAcknowledgeMsgData msgData;
	memset(&msgData, 0, sizeof(msgData));

	msgData.cause.causeValue = g_frRelCmpAckInfo->cause;

	GtpV2Stack_buildGtpV2Message(gtpStack_gp, frRelCmpAckMsgBuf_p, &gtpHeader, &msgData);

	log_msg(LOG_INFO, "send %d bytes.",MsgBuffer_getBufLen(frRelCmpAckMsgBuf_p));

	int res = sendto (
			g_gtp_fd,
			MsgBuffer_getDataPointer(frRelCmpAckMsgBuf_p),
			MsgBuffer_getBufLen(frRelCmpAckMsgBuf_p), 0,
			(struct sockaddr*)(&tmme_addr),
			g_s10_serv_size);
	if (res < 0) {
		log_msg(LOG_ERROR,"Error in sendto in detach stage 3 post to next");
	}

	log_msg(LOG_INFO,"%d bytes sent. Err : %d, %s",res,errno,
			strerror(errno));

	MsgBuffer_free(frRelCmpAckMsgBuf_p);

	return SUCCESS;
}

/**
* Thread function for stage.
*/
void*
forward_relocation_complete_acknowledgement_handler(void *data)
{
	log_msg(LOG_INFO, "Forward Relocation Complete Acknowledgement Handler");

	forward_relocation_complete_acknowledgement_processing((struct FWD_REL_CMP_ACK_Q_msg *) data);

	return NULL;
}
