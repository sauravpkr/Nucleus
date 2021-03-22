 /*
 * Copyright 2021-present Infosys Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */ 
/******************************************************************************
 * mmeProcedureCtxtManager.cpp
 * This is an auto generated file.
 * Please do not edit this file.
 * All edits to be made through template source file
 * <TOP-DIR/scripts/SMCodeGen/templates/ctxtManagerTmpls/blockPoolManager.cpp.tt>
 ******************************************************************************/

#include "memPoolManager.h"
#include "contextManager/dataBlocks.h"
#include "contextManager/mmeProcedureCtxtManager.h"

using namespace cmn::memPool;

namespace mme
{
	/******************************************************************************
	* Constructor
	******************************************************************************/
	MmeProcedureCtxtManager::MmeProcedureCtxtManager(int numOfBlocks):poolManager_m(numOfBlocks)
	{
	}
	
	/******************************************************************************
	* Destructor
	******************************************************************************/
	MmeProcedureCtxtManager::~MmeProcedureCtxtManager()
	{
	}
	
	/******************************************************************************
	* Allocate MmeProcedureCtxt data block
	******************************************************************************/
	MmeProcedureCtxt* MmeProcedureCtxtManager::allocateMmeProcedureCtxt()
	{
		MmeProcedureCtxt* MmeProcedureCtxt_p = poolManager_m.allocate();
		return MmeProcedureCtxt_p;
	}
	
	/******************************************************************************
	* Deallocate a MmeProcedureCtxt data block
	******************************************************************************/
	void MmeProcedureCtxtManager::deallocateMmeProcedureCtxt(MmeProcedureCtxt* MmeProcedureCtxtp )
	{
		poolManager_m.free( MmeProcedureCtxtp );
	}
}