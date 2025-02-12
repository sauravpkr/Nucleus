/*
 * Copyright 2019-present Infosys Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/******************************************************************************
 *
 * This is an auto generated file.
 * Please do not edit this file.
 * All edits to be made through template source file
 * <TOP-DIR/scripts/GtpV2StackCodeGen/tts/msgtemplate.cpp.tt>
 ******************************************************************************/ 

#include "configurationTransferTunnelMsg.h"
#include "../ieClasses/manual/gtpV2Ie.h"
#include "../ieClasses/gtpV2IeFactory.h"
#include "../ieClasses/fContainerIe.h"
#include "../ieClasses/targetIdentificationIe.h"

ConfigurationTransferTunnelMsg::ConfigurationTransferTunnelMsg()
{
    msgType = ConfigurationTransferTunnelMsgType;
    Uint16 mandIe;
    mandIe = FContainerIeType;
    mandIe = (mandIe << 8) | 0; // eUtranTransparentContainer
    mandatoryIeSet.insert(mandIe);    mandIe = TargetIdentificationIeType;
    mandIe = (mandIe << 8) | 0; // targetEnodebId
    mandatoryIeSet.insert(mandIe);
}

ConfigurationTransferTunnelMsg::~ConfigurationTransferTunnelMsg()
{

}

bool ConfigurationTransferTunnelMsg::encodeConfigurationTransferTunnelMsg(MsgBuffer &buffer,
                        ConfigurationTransferTunnelMsgData
							const &data)
{
    bool rc = false;
    GtpV2IeHeader header;
    Uint16 startIndex = 0;
    Uint16 endIndex = 0;
    Uint16 length = 0;

    
    // Encode the Ie Header
    header.ieType = FContainerIeType;
    header.instance = 0;
    header.length = 0; // We will encode the IE first and then update the length
    GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
    startIndex = buffer.getCurrentIndex(); 
    FContainerIe eUtranTransparentContainer=
    dynamic_cast<
    FContainerIe&>(GtpV2IeFactory::getInstance().getIeObject(FContainerIeType));
    rc = eUtranTransparentContainer.encodeFContainerIe(buffer, data.eUtranTransparentContainer);
    endIndex = buffer.getCurrentIndex();
    length = endIndex - startIndex;
    
    // encode the length value now
    buffer.goToIndex(startIndex - 3);
    buffer.writeUint16(length, false);
    buffer.goToIndex(endIndex);

    if (!(rc))
    { 
        errorStream.add((char *)"Failed to encode IE: eUtranTransparentContainer\n");
        return false;
    }

    
    // Encode the Ie Header
    header.ieType = TargetIdentificationIeType;
    header.instance = 0;
    header.length = 0; // We will encode the IE first and then update the length
    GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
    startIndex = buffer.getCurrentIndex(); 
    TargetIdentificationIe targetEnodebId=
    dynamic_cast<
    TargetIdentificationIe&>(GtpV2IeFactory::getInstance().getIeObject(TargetIdentificationIeType));
    rc = targetEnodebId.encodeTargetIdentificationIe(buffer, data.targetEnodebId);
    endIndex = buffer.getCurrentIndex();
    length = endIndex - startIndex;
    
    // encode the length value now
    buffer.goToIndex(startIndex - 3);
    buffer.writeUint16(length, false);
    buffer.goToIndex(endIndex);

    if (!(rc))
    { 
        errorStream.add((char *)"Failed to encode IE: targetEnodebId\n");
        return false;
    }
    return rc;

}

bool ConfigurationTransferTunnelMsg::decodeConfigurationTransferTunnelMsg(MsgBuffer &buffer,
 ConfigurationTransferTunnelMsgData 
 &data, Uint16 length)
{

    bool rc = false;
    GtpV2IeHeader ieHeader;
  
    set<Uint16> mandatoryIeLocalList = mandatoryIeSet;
    while (buffer.lengthLeft() > IE_HEADER_SIZE)
    {
        GtpV2Ie::decodeGtpV2IeHeader(buffer, ieHeader);
        if (ieHeader.length > buffer.lengthLeft())
        {
            // We do not have enough bytes left in the message for this IE
            errorStream.add((char *)"IE Length exceeds beyond message boundary\n");
            errorStream.add((char *)"  Offending IE Type: ");
            errorStream.add(ieHeader.ieType);
            errorStream.add((char *)"\n  Ie Length in Header: ");
            errorStream.add(ieHeader.length);
            errorStream.add((char *)"\n  Bytes left in message: ");
            errorStream.add(buffer.lengthLeft());
            errorStream.endOfLine();
            return false;
        }

        switch (ieHeader.ieType){
     
            case FContainerIeType:
            {
                FContainerIe ieObject =
                dynamic_cast<
                FContainerIe&>(GtpV2IeFactory::getInstance().getIeObject(FContainerIeType));

                if(ieHeader.instance == 0)
                {
                    rc = ieObject.decodeFContainerIe(buffer, data.eUtranTransparentContainer, ieHeader.length);

                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: eUtranTransparentContainer\n");
                        return false;
                    }
                }

                else
                {
                    // Unknown IE instance print error
                    errorStream.add((char *)"Unknown IE Type: ");
                    errorStream.add(ieHeader.ieType);
                    errorStream.endOfLine();
                    buffer.skipBytes(ieHeader.length);
                }
                break;
            }
     
            case TargetIdentificationIeType:
            {
                TargetIdentificationIe ieObject =
                dynamic_cast<
                TargetIdentificationIe&>(GtpV2IeFactory::getInstance().getIeObject(TargetIdentificationIeType));

                if(ieHeader.instance == 0)
                {
                    rc = ieObject.decodeTargetIdentificationIe(buffer, data.targetEnodebId, ieHeader.length);

                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: targetEnodebId\n");
                        return false;
                    }
                }

                else
                {
                    // Unknown IE instance print error
                    errorStream.add((char *)"Unknown IE Type: ");
                    errorStream.add(ieHeader.ieType);
                    errorStream.endOfLine();
                    buffer.skipBytes(ieHeader.length);
                }
                break;
            }

            default:
            {
                // Unknown IE print error
                errorStream.add((char *)"Unknown IE Type: ");
                errorStream.add(ieHeader.ieType);
                errorStream.endOfLine();
                buffer.skipBytes(ieHeader.length);
            }
        }
    }
    return rc; // TODO validations
}

void ConfigurationTransferTunnelMsg::
displayConfigurationTransferTunnelMsgData_v(ConfigurationTransferTunnelMsgData const &data, Debug &stream)
{
    stream.incrIndent();
    stream.add((char *)"ConfigurationTransferTunnelMsg:");
    stream.endOfLine();
    stream.incrIndent();
        
    
    stream.add((char *)"IE - eUtranTransparentContainer:");
    stream.endOfLine();
    FContainerIe eUtranTransparentContainer=
    dynamic_cast<
    FContainerIe&>(GtpV2IeFactory::getInstance().getIeObject(FContainerIeType));
    eUtranTransparentContainer.displayFContainerIe_v(data.eUtranTransparentContainer, stream);

    stream.add((char *)"IE - targetEnodebId:");
    stream.endOfLine();
    TargetIdentificationIe targetEnodebId=
    dynamic_cast<
    TargetIdentificationIe&>(GtpV2IeFactory::getInstance().getIeObject(TargetIdentificationIeType));
    targetEnodebId.displayTargetIdentificationIe_v(data.targetEnodebId, stream);


    stream.decrIndent();
    stream.decrIndent();
}

