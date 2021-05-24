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

#include "contextRequestMsg.h"
#include "../ieClasses/manual/gtpV2Ie.h"
#include "../ieClasses/gtpV2IeFactory.h"
#include "../ieClasses/imsiIe.h"
#include "../ieClasses/gutiIe.h"
#include "../ieClasses/fTeidIe.h"
#include "../ieClasses/ratTypeIe.h"
#include "../ieClasses/indicationIe.h"
#include "../ieClasses/localDistinguishedNameIe.h"

ContextRequestMsg::ContextRequestMsg()
{
    msgType = ContextRequestMsgType;

}

ContextRequestMsg::~ContextRequestMsg()
{

}

bool ContextRequestMsg::encodeContextRequestMsg(MsgBuffer &buffer,
                        ContextRequestMsgData
							const &data)
{
    bool rc = false;
    GtpV2IeHeader header;
    Uint16 startIndex = 0;
    Uint16 endIndex = 0;
    Uint16 length = 0;

    if (data.imsiIePresent)
    {
        
        // Encode the Ie Header
        header.ieType = ImsiIeType;
        header.instance = 0;
        header.length = 0; // We will encode the IE first and then update the length
        GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
        startIndex = buffer.getCurrentIndex(); 
        ImsiIe imsi=
        dynamic_cast<
        ImsiIe&>(GtpV2IeFactory::getInstance().getIeObject(ImsiIeType));
        rc = imsi.encodeImsiIe(buffer, data.imsi);
        endIndex = buffer.getCurrentIndex();
        length = endIndex - startIndex;
        
        // encode the length value now
        buffer.goToIndex(startIndex - 3);
        buffer.writeUint16(length, false);
        buffer.goToIndex(endIndex);

        if (!(rc))
        { 
            errorStream.add((char *)"Failed to encode IE: imsi\n");
            return false;
        }
    }

    if (data.gutiIePresent)
    {
        
        // Encode the Ie Header
        header.ieType = GutiIeType;
        header.instance = 0;
        header.length = 0; // We will encode the IE first and then update the length
        GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
        startIndex = buffer.getCurrentIndex(); 
        GutiIe guti=
        dynamic_cast<
        GutiIe&>(GtpV2IeFactory::getInstance().getIeObject(GutiIeType));
        rc = guti.encodeGutiIe(buffer, data.guti);
        endIndex = buffer.getCurrentIndex();
        length = endIndex - startIndex;
        
        // encode the length value now
        buffer.goToIndex(startIndex - 3);
        buffer.writeUint16(length, false);
        buffer.goToIndex(endIndex);

        if (!(rc))
        { 
            errorStream.add((char *)"Failed to encode IE: guti\n");
            return false;
        }
    }

    if (data.s3S16S10N26AddressAndTeidForControlPlaneIePresent)
    {
        
        // Encode the Ie Header
        header.ieType = FTeidIeType;
        header.instance = 0;
        header.length = 0; // We will encode the IE first and then update the length
        GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
        startIndex = buffer.getCurrentIndex(); 
        FTeidIe s3S16S10N26AddressAndTeidForControlPlane=
        dynamic_cast<
        FTeidIe&>(GtpV2IeFactory::getInstance().getIeObject(FTeidIeType));
        rc = s3S16S10N26AddressAndTeidForControlPlane.encodeFTeidIe(buffer, data.s3S16S10N26AddressAndTeidForControlPlane);
        endIndex = buffer.getCurrentIndex();
        length = endIndex - startIndex;
        
        // encode the length value now
        buffer.goToIndex(startIndex - 3);
        buffer.writeUint16(length, false);
        buffer.goToIndex(endIndex);

        if (!(rc))
        { 
            errorStream.add((char *)"Failed to encode IE: s3S16S10N26AddressAndTeidForControlPlane\n");
            return false;
        }
    }

    if (data.ratTypeIePresent)
    {
        
        // Encode the Ie Header
        header.ieType = RatTypeIeType;
        header.instance = 0;
        header.length = 0; // We will encode the IE first and then update the length
        GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
        startIndex = buffer.getCurrentIndex(); 
        RatTypeIe ratType=
        dynamic_cast<
        RatTypeIe&>(GtpV2IeFactory::getInstance().getIeObject(RatTypeIeType));
        rc = ratType.encodeRatTypeIe(buffer, data.ratType);
        endIndex = buffer.getCurrentIndex();
        length = endIndex - startIndex;
        
        // encode the length value now
        buffer.goToIndex(startIndex - 3);
        buffer.writeUint16(length, false);
        buffer.goToIndex(endIndex);

        if (!(rc))
        { 
            errorStream.add((char *)"Failed to encode IE: ratType\n");
            return false;
        }
    }

    if (data.indicationIePresent)
    {
        
        // Encode the Ie Header
        header.ieType = IndicationIeType;
        header.instance = 0;
        header.length = 0; // We will encode the IE first and then update the length
        GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
        startIndex = buffer.getCurrentIndex(); 
        IndicationIe indication=
        dynamic_cast<
        IndicationIe&>(GtpV2IeFactory::getInstance().getIeObject(IndicationIeType));
        rc = indication.encodeIndicationIe(buffer, data.indication);
        endIndex = buffer.getCurrentIndex();
        length = endIndex - startIndex;
        
        // encode the length value now
        buffer.goToIndex(startIndex - 3);
        buffer.writeUint16(length, false);
        buffer.goToIndex(endIndex);

        if (!(rc))
        { 
            errorStream.add((char *)"Failed to encode IE: indication\n");
            return false;
        }
    }

    if (data.mmeS4SgsnLdnIePresent)
    {
        
        // Encode the Ie Header
        header.ieType = LocalDistinguishedNameIeType;
        header.instance = 0;
        header.length = 0; // We will encode the IE first and then update the length
        GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
        startIndex = buffer.getCurrentIndex(); 
        LocalDistinguishedNameIe mmeS4SgsnLdn=
        dynamic_cast<
        LocalDistinguishedNameIe&>(GtpV2IeFactory::getInstance().getIeObject(LocalDistinguishedNameIeType));
        rc = mmeS4SgsnLdn.encodeLocalDistinguishedNameIe(buffer, data.mmeS4SgsnLdn);
        endIndex = buffer.getCurrentIndex();
        length = endIndex - startIndex;
        
        // encode the length value now
        buffer.goToIndex(startIndex - 3);
        buffer.writeUint16(length, false);
        buffer.goToIndex(endIndex);

        if (!(rc))
        { 
            errorStream.add((char *)"Failed to encode IE: mmeS4SgsnLdn\n");
            return false;
        }
    }
    return rc;

}

bool ContextRequestMsg::decodeContextRequestMsg(MsgBuffer &buffer,
 ContextRequestMsgData 
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
     
            case ImsiIeType:
            {
                ImsiIe ieObject =
                dynamic_cast<
                ImsiIe&>(GtpV2IeFactory::getInstance().getIeObject(ImsiIeType));

                if(ieHeader.instance == 0)
                {
                    rc = ieObject.decodeImsiIe(buffer, data.imsi, ieHeader.length);

                    data.imsiIePresent = true;
                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: imsi\n");
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
     
            case GutiIeType:
            {
                GutiIe ieObject =
                dynamic_cast<
                GutiIe&>(GtpV2IeFactory::getInstance().getIeObject(GutiIeType));

                if(ieHeader.instance == 0)
                {
                    rc = ieObject.decodeGutiIe(buffer, data.guti, ieHeader.length);

                    data.gutiIePresent = true;
                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: guti\n");
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
     
            case FTeidIeType:
            {
                FTeidIe ieObject =
                dynamic_cast<
                FTeidIe&>(GtpV2IeFactory::getInstance().getIeObject(FTeidIeType));

                if(ieHeader.instance == 0)
                {
                    rc = ieObject.decodeFTeidIe(buffer, data.s3S16S10N26AddressAndTeidForControlPlane, ieHeader.length);

                    data.s3S16S10N26AddressAndTeidForControlPlaneIePresent = true;
                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: s3S16S10N26AddressAndTeidForControlPlane\n");
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
     
            case RatTypeIeType:
            {
                RatTypeIe ieObject =
                dynamic_cast<
                RatTypeIe&>(GtpV2IeFactory::getInstance().getIeObject(RatTypeIeType));

                if(ieHeader.instance == 0)
                {
                    rc = ieObject.decodeRatTypeIe(buffer, data.ratType, ieHeader.length);

                    data.ratTypeIePresent = true;
                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: ratType\n");
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
     
            case IndicationIeType:
            {
                IndicationIe ieObject =
                dynamic_cast<
                IndicationIe&>(GtpV2IeFactory::getInstance().getIeObject(IndicationIeType));

                if(ieHeader.instance == 0)
                {
                    rc = ieObject.decodeIndicationIe(buffer, data.indication, ieHeader.length);

                    data.indicationIePresent = true;
                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: indication\n");
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
     
            case LocalDistinguishedNameIeType:
            {
                LocalDistinguishedNameIe ieObject =
                dynamic_cast<
                LocalDistinguishedNameIe&>(GtpV2IeFactory::getInstance().getIeObject(LocalDistinguishedNameIeType));

                if(ieHeader.instance == 0)
                {
                    rc = ieObject.decodeLocalDistinguishedNameIe(buffer, data.mmeS4SgsnLdn, ieHeader.length);

                    data.mmeS4SgsnLdnIePresent = true;
                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: mmeS4SgsnLdn\n");
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

void ContextRequestMsg::
displayContextRequestMsgData_v(ContextRequestMsgData const &data, Debug &stream)
{
    stream.incrIndent();
    stream.add((char *)"ContextRequestMsg:");
    stream.endOfLine();
    stream.incrIndent();
        
    
    if (data.imsiIePresent)
    {


        stream.add((char *)"IE - imsi:");
        stream.endOfLine();
        ImsiIe imsi=
        dynamic_cast<
        ImsiIe&>(GtpV2IeFactory::getInstance().getIeObject(ImsiIeType));
        imsi.displayImsiIe_v(data.imsi, stream);

    }
    if (data.gutiIePresent)
    {


        stream.add((char *)"IE - guti:");
        stream.endOfLine();
        GutiIe guti=
        dynamic_cast<
        GutiIe&>(GtpV2IeFactory::getInstance().getIeObject(GutiIeType));
        guti.displayGutiIe_v(data.guti, stream);

    }
    if (data.s3S16S10N26AddressAndTeidForControlPlaneIePresent)
    {


        stream.add((char *)"IE - s3S16S10N26AddressAndTeidForControlPlane:");
        stream.endOfLine();
        FTeidIe s3S16S10N26AddressAndTeidForControlPlane=
        dynamic_cast<
        FTeidIe&>(GtpV2IeFactory::getInstance().getIeObject(FTeidIeType));
        s3S16S10N26AddressAndTeidForControlPlane.displayFTeidIe_v(data.s3S16S10N26AddressAndTeidForControlPlane, stream);

    }
    if (data.ratTypeIePresent)
    {


        stream.add((char *)"IE - ratType:");
        stream.endOfLine();
        RatTypeIe ratType=
        dynamic_cast<
        RatTypeIe&>(GtpV2IeFactory::getInstance().getIeObject(RatTypeIeType));
        ratType.displayRatTypeIe_v(data.ratType, stream);

    }
    if (data.indicationIePresent)
    {


        stream.add((char *)"IE - indication:");
        stream.endOfLine();
        IndicationIe indication=
        dynamic_cast<
        IndicationIe&>(GtpV2IeFactory::getInstance().getIeObject(IndicationIeType));
        indication.displayIndicationIe_v(data.indication, stream);

    }
    if (data.mmeS4SgsnLdnIePresent)
    {


        stream.add((char *)"IE - mmeS4SgsnLdn:");
        stream.endOfLine();
        LocalDistinguishedNameIe mmeS4SgsnLdn=
        dynamic_cast<
        LocalDistinguishedNameIe&>(GtpV2IeFactory::getInstance().getIeObject(LocalDistinguishedNameIeType));
        mmeS4SgsnLdn.displayLocalDistinguishedNameIe_v(data.mmeS4SgsnLdn, stream);

    }

    stream.decrIndent();
    stream.decrIndent();
}

