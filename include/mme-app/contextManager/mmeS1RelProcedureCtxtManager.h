 /*
 * Copyright 2021-present, Infosys Limited.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __MmeS1RelProcedureCtxtManager__
#define __MmeS1RelProcedureCtxtManager__
/******************************************************
* mmeS1RelProcedureCtxtManager.h
 * This is an auto generated file.
 * Please do not edit this file.
 * All edits to be made through template source file
 * <TOP-DIR/scripts/SMCodeGen/templates/ctxtManagerTmpls/blockPoolManager.h.tt>
 ***************************************/
#include "memPoolManager.h"

namespace mme
{
	class MmeS1RelProcedureCtxt;
	class MmeS1RelProcedureCtxtManager
	{
		public:
			/****************************************
			* MmeS1RelProcedureCtxtManager
			*  constructor
			****************************************/
			MmeS1RelProcedureCtxtManager(int numOfBlocks);
			
			/****************************************
			* MmeS1RelProcedureCtxtManager
			*    Destructor
			****************************************/
			~MmeS1RelProcedureCtxtManager();
			
			/******************************************
			 * allocateMmeS1RelProcedureCtxt
			 * allocate MmeS1RelProcedureCtxt data block
			 ******************************************/
			MmeS1RelProcedureCtxt* allocateMmeS1RelProcedureCtxt();
			
			/******************************************
			 * deallocateMmeS1RelProcedureCtxt
			 * deallocate a MmeS1RelProcedureCtxt data block
			 ******************************************/
			void deallocateMmeS1RelProcedureCtxt(MmeS1RelProcedureCtxt* MmeS1RelProcedureCtxtp );
	
		private:
			cmn::memPool::MemPoolManager<MmeS1RelProcedureCtxt> poolManager_m;
	};
};

#endif
		
		
