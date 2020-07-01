
/*
 * Copyright 2019-present, Infosys Limited.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef DGM_BLOCKSTRUCTURES_H
#define DGM_BLOCKSTRUCTURES_H
/**************************************
 *
 * This is an auto generated file.
 * Please do not edit this file.
 * All edits to be made through template source file
 * <TOP-DIR/scripts/SMCodeGen/templates/ctxtManagerTmpls/dataBlocks.h.tt>
 ***************************************/
#include "permDataBlock.h"
#include "tempDataBlock.h"
#include <s1_common_types.h>

namespace mme
{
	class EnbContext;
	 
	class EnbContext:public SM::PermDataBlock
	{
		public:
	
			/****************************************
			* EnbContext
			*    constructor
			****************************************/
			EnbContext();
			
			/****************************************
			* ~EnbContext
			*    destructor
			****************************************/
			~EnbContext();
			
			/****************************************
			* setEnbFd
			*    set enbFd to EnbContext
			****************************************/
			void setEnbFd(int enbFd_i);
			
			/****************************************
			* getEnbFd
			*    get enbFd from EnbContext
			****************************************/
			int getEnbFd()const;				
			
			/****************************************
			* setEnbId
			*    set enbId to EnbContext
			****************************************/
			void setEnbId(int enbId_i);
			
			/****************************************
			* getEnbId
			*    get enbId from EnbContext
			****************************************/
			int getEnbId()const;				
			
			/****************************************
			* setS1apEnbUeId
			*    set s1apEnbUeId to EnbContext
			****************************************/
			void setS1apEnbUeId(int s1apEnbUeId_i);
			
			/****************************************
			* getS1apEnbUeId
			*    get s1apEnbUeId from EnbContext
			****************************************/
			int getS1apEnbUeId()const;				
			
			/****************************************
			* setContextID
			*    set contextID to EnbContext
			****************************************/
			void setContextID(uint32_t contextID_i);
			
			/****************************************
			* getContextID
			*    get contextID from EnbContext
			****************************************/
			uint32_t getContextID()const;				
			
			/****************************************
			* setTai
			*    set tai to EnbContext
			****************************************/
			void setTai(const TAI& tai_i);
			
			/****************************************
			* getTai
			*    get tai from EnbContext
			****************************************/
			const TAI& getTai()const;				
			
		
		private:
		
			// DataName
			int enbFd_m;
			
			// DataName
			int enbId_m;
			
			// DataName
			int s1apEnbUeId_m;
			
			// DataName
			uint32_t contextID_m;
			
			// DataName
			TAI tai_m;
			
	};
	
	
} // mme
#endif
