

 /*
 * Copyright 2021-present Infosys Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */
 
 /******************************************************
 * s1InterMmeHandoverStates.h
 * This is an auto generated file.
 * Please do not edit this file.
 * All edits to be made through template source file
 * <TOP-DIR/scripts/SMCodeGen/templates/stateMachineTmpls/state.h.tt>
 ******************************************************/
 #ifndef __S1_INTER_MME_HANDOVER__
 #define __S1_INTER_MME_HANDOVER__

 #include "state.h"

 namespace mme {
	class InterS1HoStartSrcMme : public SM::State
	{
		public:
			/******************************************
			* Instance 
			*    Creates static instance for the state
			*******************************************/
			static InterS1HoStartSrcMme* Instance();

			/****************************************
			* InterS1HoStartSrcMme
			*    Destructor
			****************************************/
			~InterS1HoStartSrcMme();			
			
			/******************************************
			* initialize
			*  Initializes action handlers for the state
			* and next state
			******************************************/
			void initialize();

			/*****************************************
			* returns stateId
			*****************************************/
			uint16_t getStateId() const;

			/*****************************************
			* returns stateName
			*****************************************/
			const char* getStateName() const;

		protected:
			/****************************************
			* InterS1HoStartSrcMme
			*    Protected constructor
			****************************************/
			InterS1HoStartSrcMme();  
	};
	
	class S1FrWfHoRequestRes : public SM::State
	{
		public:
			/******************************************
			* Instance 
			*    Creates static instance for the state
			*******************************************/
			static S1FrWfHoRequestRes* Instance();

			/****************************************
			* S1FrWfHoRequestRes
			*    Destructor
			****************************************/
			~S1FrWfHoRequestRes();			
			
			/******************************************
			* initialize
			*  Initializes action handlers for the state
			* and next state
			******************************************/
			void initialize();

			/*****************************************
			* returns stateId
			*****************************************/
			uint16_t getStateId() const;

			/*****************************************
			* returns stateName
			*****************************************/
			const char* getStateName() const;

		protected:
			/****************************************
			* S1FrWfHoRequestRes
			*    Protected constructor
			****************************************/
			S1FrWfHoRequestRes();  
	};
	
	class S1HoWfEnbStatusTransfer : public SM::State
	{
		public:
			/******************************************
			* Instance 
			*    Creates static instance for the state
			*******************************************/
			static S1HoWfEnbStatusTransfer* Instance();

			/****************************************
			* S1HoWfEnbStatusTransfer
			*    Destructor
			****************************************/
			~S1HoWfEnbStatusTransfer();			
			
			/******************************************
			* initialize
			*  Initializes action handlers for the state
			* and next state
			******************************************/
			void initialize();

			/*****************************************
			* returns stateId
			*****************************************/
			uint16_t getStateId() const;

			/*****************************************
			* returns stateName
			*****************************************/
			const char* getStateName() const;

		protected:
			/****************************************
			* S1HoWfEnbStatusTransfer
			*    Protected constructor
			****************************************/
			S1HoWfEnbStatusTransfer();  
	};
	
	class S1HoWfFwdAccCtxtAck : public SM::State
	{
		public:
			/******************************************
			* Instance 
			*    Creates static instance for the state
			*******************************************/
			static S1HoWfFwdAccCtxtAck* Instance();

			/****************************************
			* S1HoWfFwdAccCtxtAck
			*    Destructor
			****************************************/
			~S1HoWfFwdAccCtxtAck();			
			
			/******************************************
			* initialize
			*  Initializes action handlers for the state
			* and next state
			******************************************/
			void initialize();

			/*****************************************
			* returns stateId
			*****************************************/
			uint16_t getStateId() const;

			/*****************************************
			* returns stateName
			*****************************************/
			const char* getStateName() const;

		protected:
			/****************************************
			* S1HoWfFwdAccCtxtAck
			*    Protected constructor
			****************************************/
			S1HoWfFwdAccCtxtAck();  
	};
	
	class S1HoWfFwdRelComp : public SM::State
	{
		public:
			/******************************************
			* Instance 
			*    Creates static instance for the state
			*******************************************/
			static S1HoWfFwdRelComp* Instance();

			/****************************************
			* S1HoWfFwdRelComp
			*    Destructor
			****************************************/
			~S1HoWfFwdRelComp();			
			
			/******************************************
			* initialize
			*  Initializes action handlers for the state
			* and next state
			******************************************/
			void initialize();

			/*****************************************
			* returns stateId
			*****************************************/
			uint16_t getStateId() const;

			/*****************************************
			* returns stateName
			*****************************************/
			const char* getStateName() const;

		protected:
			/****************************************
			* S1HoWfFwdRelComp
			*    Protected constructor
			****************************************/
			S1HoWfFwdRelComp();  
	};
	
	class InterS1HoStartTgtMme : public SM::State
	{
		public:
			/******************************************
			* Instance 
			*    Creates static instance for the state
			*******************************************/
			static InterS1HoStartTgtMme* Instance();

			/****************************************
			* InterS1HoStartTgtMme
			*    Destructor
			****************************************/
			~InterS1HoStartTgtMme();			
			
			/******************************************
			* initialize
			*  Initializes action handlers for the state
			* and next state
			******************************************/
			void initialize();

			/*****************************************
			* returns stateId
			*****************************************/
			uint16_t getStateId() const;

			/*****************************************
			* returns stateName
			*****************************************/
			const char* getStateName() const;

		protected:
			/****************************************
			* InterS1HoStartTgtMme
			*    Protected constructor
			****************************************/
			InterS1HoStartTgtMme();  
	};
	
	class S1HoWfHoReqAck : public SM::State
	{
		public:
			/******************************************
			* Instance 
			*    Creates static instance for the state
			*******************************************/
			static S1HoWfHoReqAck* Instance();

			/****************************************
			* S1HoWfHoReqAck
			*    Destructor
			****************************************/
			~S1HoWfHoReqAck();			
			
			/******************************************
			* initialize
			*  Initializes action handlers for the state
			* and next state
			******************************************/
			void initialize();

			/*****************************************
			* returns stateId
			*****************************************/
			uint16_t getStateId() const;

			/*****************************************
			* returns stateName
			*****************************************/
			const char* getStateName() const;

		protected:
			/****************************************
			* S1HoWfHoReqAck
			*    Protected constructor
			****************************************/
			S1HoWfHoReqAck();  
	};
	
	class S1HoWfHoFwdAccCntxNoti : public SM::State
	{
		public:
			/******************************************
			* Instance 
			*    Creates static instance for the state
			*******************************************/
			static S1HoWfHoFwdAccCntxNoti* Instance();

			/****************************************
			* S1HoWfHoFwdAccCntxNoti
			*    Destructor
			****************************************/
			~S1HoWfHoFwdAccCntxNoti();			
			
			/******************************************
			* initialize
			*  Initializes action handlers for the state
			* and next state
			******************************************/
			void initialize();

			/*****************************************
			* returns stateId
			*****************************************/
			uint16_t getStateId() const;

			/*****************************************
			* returns stateName
			*****************************************/
			const char* getStateName() const;

		protected:
			/****************************************
			* S1HoWfHoFwdAccCntxNoti
			*    Protected constructor
			****************************************/
			S1HoWfHoFwdAccCntxNoti();  
	};
	
	class S1HoWfHoNotifyFromTargetEnb : public SM::State
	{
		public:
			/******************************************
			* Instance 
			*    Creates static instance for the state
			*******************************************/
			static S1HoWfHoNotifyFromTargetEnb* Instance();

			/****************************************
			* S1HoWfHoNotifyFromTargetEnb
			*    Destructor
			****************************************/
			~S1HoWfHoNotifyFromTargetEnb();			
			
			/******************************************
			* initialize
			*  Initializes action handlers for the state
			* and next state
			******************************************/
			void initialize();

			/*****************************************
			* returns stateId
			*****************************************/
			uint16_t getStateId() const;

			/*****************************************
			* returns stateName
			*****************************************/
			const char* getStateName() const;

		protected:
			/****************************************
			* S1HoWfHoNotifyFromTargetEnb
			*    Protected constructor
			****************************************/
			S1HoWfHoNotifyFromTargetEnb();  
	};
	
	class S1HoWfMbRespFromSgw : public SM::State
	{
		public:
			/******************************************
			* Instance 
			*    Creates static instance for the state
			*******************************************/
			static S1HoWfMbRespFromSgw* Instance();

			/****************************************
			* S1HoWfMbRespFromSgw
			*    Destructor
			****************************************/
			~S1HoWfMbRespFromSgw();			
			
			/******************************************
			* initialize
			*  Initializes action handlers for the state
			* and next state
			******************************************/
			void initialize();

			/*****************************************
			* returns stateId
			*****************************************/
			uint16_t getStateId() const;

			/*****************************************
			* returns stateName
			*****************************************/
			const char* getStateName() const;

		protected:
			/****************************************
			* S1HoWfMbRespFromSgw
			*    Protected constructor
			****************************************/
			S1HoWfMbRespFromSgw();  
	};
	
};
#endif // __S1_INTER_MME_HANDOVER__
