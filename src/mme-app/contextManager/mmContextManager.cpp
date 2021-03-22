 /*
 * Copyright 2021-present Infosys Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */ 
/******************************************************************************
 * mmContextManager.cpp
 * This is an auto generated file.
 * Please do not edit this file.
 * All edits to be made through template source file
 * <TOP-DIR/scripts/SMCodeGen/templates/ctxtManagerTmpls/blockPoolManager.cpp.tt>
 ******************************************************************************/

#include "memPoolManager.h"
#include "contextManager/dataBlocks.h"
#include "contextManager/mmContextManager.h"

using namespace cmn::memPool;

namespace mme
{
	/******************************************************************************
	* Constructor
	******************************************************************************/
	MmContextManager::MmContextManager(int numOfBlocks):poolManager_m(numOfBlocks)
	{
	}
	
	/******************************************************************************
	* Destructor
	******************************************************************************/
	MmContextManager::~MmContextManager()
	{
	}
	
	/******************************************************************************
	* Allocate MmContext data block
	******************************************************************************/
	MmContext* MmContextManager::allocateMmContext()
	{
		MmContext* MmContext_p = poolManager_m.allocate();
		return MmContext_p;
	}
	
	/******************************************************************************
	* Deallocate a MmContext data block
	******************************************************************************/
	void MmContextManager::deallocateMmContext(MmContext* MmContextp )
	{
		poolManager_m.free( MmContextp );
	}
}