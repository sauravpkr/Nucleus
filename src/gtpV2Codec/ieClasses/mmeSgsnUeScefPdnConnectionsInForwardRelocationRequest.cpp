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
 * <TOP-DIR/scripts/GtpV2StackCodeGen/tts/grpieinsttemplate.cpp.tt>
 ******************************************************************************/
 
#include "mmeSgsnUeScefPdnConnectionsInForwardRelocationRequest.h"
#include "manual/gtpV2Ie.h"
#include "gtpV2IeFactory.h"
#include "apnIe.h"
#include "ebiIe.h"
#include "nodeIdentifierIe.h"

MmeSgsnUeScefPdnConnectionsInForwardRelocationRequest::
MmeSgsnUeScefPdnConnectionsInForwardRelocationRequest()
{
    Uint16 mandIe;
    mandIe = ApnIeType;
    mandIe = (mandIe << 8) | 0; // apn
    mandatoryIeSet.insert(mandIe);
    mandIe = EbiIeType;
    mandIe = (mandIe << 8) | 0; // defaultEpsBearerId
    mandatoryIeSet.insert(mandIe);
    mandIe = NodeIdentifierIeType;
    mandIe = (mandIe << 8) | 0; // scefId
    mandatoryIeSet.insert(mandIe);

}

MmeSgsnUeScefPdnConnectionsInForwardRelocationRequest::
~MmeSgsnUeScefPdnConnectionsInForwardRelocationRequest()
{

}
bool MmeSgsnUeScefPdnConnectionsInForwardRelocationRequest::
encodeMmeSgsnUeScefPdnConnectionsInForwardRelocationRequest(MsgBuffer &buffer,
                         MmeSgsnUeScefPdnConnectionsInForwardRelocationRequestData
                          const &data)
{
    bool rc = false;
    GtpV2IeHeader header;
    Uint16 startIndex = 0;
    Uint16 endIndex = 0;
    Uint16 length = 0;


    
    // Encode the Ie Header
    header.ieType = ApnIeType;
    header.instance = 0;
    header.length = 0; // We will encode the IE first and then update the length
    GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
    startIndex = buffer.getCurrentIndex(); 
    ApnIe apn=
    dynamic_cast<
    ApnIe&>(GtpV2IeFactory::getInstance().getIeObject(ApnIeType));
    rc = apn.encodeApnIe(buffer, data.apn);
    endIndex = buffer.getCurrentIndex();
    length = endIndex - startIndex;
    
    // encode the length value now
    buffer.goToIndex(startIndex - 3);
    buffer.writeUint16(length, false);
    buffer.goToIndex(endIndex);
    if (!(rc))
    {
        errorStream.add((char *)"Failed to encode IE: apn\n");
        return false;
    }

    
    // Encode the Ie Header
    header.ieType = EbiIeType;
    header.instance = 0;
    header.length = 0; // We will encode the IE first and then update the length
    GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
    startIndex = buffer.getCurrentIndex(); 
    EbiIe defaultEpsBearerId=
    dynamic_cast<
    EbiIe&>(GtpV2IeFactory::getInstance().getIeObject(EbiIeType));
    rc = defaultEpsBearerId.encodeEbiIe(buffer, data.defaultEpsBearerId);
    endIndex = buffer.getCurrentIndex();
    length = endIndex - startIndex;
    
    // encode the length value now
    buffer.goToIndex(startIndex - 3);
    buffer.writeUint16(length, false);
    buffer.goToIndex(endIndex);
    if (!(rc))
    {
        errorStream.add((char *)"Failed to encode IE: defaultEpsBearerId\n");
        return false;
    }

    
    // Encode the Ie Header
    header.ieType = NodeIdentifierIeType;
    header.instance = 0;
    header.length = 0; // We will encode the IE first and then update the length
    GtpV2Ie::encodeGtpV2IeHeader(buffer, header);
    startIndex = buffer.getCurrentIndex(); 
    NodeIdentifierIe scefId=
    dynamic_cast<
    NodeIdentifierIe&>(GtpV2IeFactory::getInstance().getIeObject(NodeIdentifierIeType));
    rc = scefId.encodeNodeIdentifierIe(buffer, data.scefId);
    endIndex = buffer.getCurrentIndex();
    length = endIndex - startIndex;
    
    // encode the length value now
    buffer.goToIndex(startIndex - 3);
    buffer.writeUint16(length, false);
    buffer.goToIndex(endIndex);
    if (!(rc))
    {
        errorStream.add((char *)"Failed to encode IE: scefId\n");
        return false;
    }
    return rc;
}

bool MmeSgsnUeScefPdnConnectionsInForwardRelocationRequest::
decodeMmeSgsnUeScefPdnConnectionsInForwardRelocationRequest(MsgBuffer &buffer,
                         MmeSgsnUeScefPdnConnectionsInForwardRelocationRequestData 
                         &data, Uint16 length)
{
    Uint16 groupedIeBoundary = length + buffer.getCurrentIndex();
    bool rc = false;
    GtpV2IeHeader ieHeader;
    set<Uint16> mandatoryIeLocalList = mandatoryIeSet;
    while ((buffer.lengthLeft() > IE_HEADER_SIZE) &&
                   (buffer.getCurrentIndex() < groupedIeBoundary))
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
            case ApnIeType:
            {
                ApnIe ieObject =
                dynamic_cast<
                ApnIe&>(GtpV2IeFactory::getInstance().
                         getIeObject(ApnIeType));

                if(ieHeader.instance == 0)
                {

                    rc = ieObject.decodeApnIe(buffer, data.apn, ieHeader.length);

                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: apn\n");
                        return false;
                    }
                    Uint16 mandIe = ApnIeType;
                    mandIe = (mandIe << 8) | 0;
                    mandatoryIeLocalList.erase(mandIe);
                }
                else
                {
                    // Unknown IE instance print error TODO
                    errorStream.add((char *)"Unknown IE Type: ");
                    errorStream.add(ieHeader.ieType);
                    errorStream.endOfLine();
                    buffer.skipBytes(ieHeader.length);
                }
                break;
            }
            case EbiIeType:
            {
                EbiIe ieObject =
                dynamic_cast<
                EbiIe&>(GtpV2IeFactory::getInstance().
                         getIeObject(EbiIeType));

                if(ieHeader.instance == 0)
                {

                    rc = ieObject.decodeEbiIe(buffer, data.defaultEpsBearerId, ieHeader.length);

                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: defaultEpsBearerId\n");
                        return false;
                    }
                    Uint16 mandIe = EbiIeType;
                    mandIe = (mandIe << 8) | 0;
                    mandatoryIeLocalList.erase(mandIe);
                }
                else
                {
                    // Unknown IE instance print error TODO
                    errorStream.add((char *)"Unknown IE Type: ");
                    errorStream.add(ieHeader.ieType);
                    errorStream.endOfLine();
                    buffer.skipBytes(ieHeader.length);
                }
                break;
            }
            case NodeIdentifierIeType:
            {
                NodeIdentifierIe ieObject =
                dynamic_cast<
                NodeIdentifierIe&>(GtpV2IeFactory::getInstance().
                         getIeObject(NodeIdentifierIeType));

                if(ieHeader.instance == 0)
                {

                    rc = ieObject.decodeNodeIdentifierIe(buffer, data.scefId, ieHeader.length);

                    if (!(rc))
                    {
                        errorStream.add((char *)"Failed to decode IE: scefId\n");
                        return false;
                    }
                    Uint16 mandIe = NodeIdentifierIeType;
                    mandIe = (mandIe << 8) | 0;
                    mandatoryIeLocalList.erase(mandIe);
                }
                else
                {
                    // Unknown IE instance print error TODO
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
    if (!mandatoryIeLocalList.empty())
    {
        // some mandatory IEs are missing
        errorStream.add((char *)"Missing Mandatory IEs:");
        errorStream.endOfLine();
        while (!mandatoryIeLocalList.empty())
        {
            Uint16 missingMandIe = *mandatoryIeLocalList.begin ();
            mandatoryIeLocalList.erase (mandatoryIeLocalList.begin ());
            Uint16 missingInstance = missingMandIe & 0x00FF;
            Uint16 missingIeType = (missingMandIe >> 8);
            errorStream.add ((char *)"Missing Ie type: ");
            errorStream.add (missingIeType);
            errorStream.add ((char *)"  Instance: ");
            errorStream.add (missingInstance);
            errorStream.endOfLine();
        }
        rc = false;
    
    }
    return rc; 
}

void MmeSgsnUeScefPdnConnectionsInForwardRelocationRequest::
displayMmeSgsnUeScefPdnConnectionsInForwardRelocationRequestData_v
(MmeSgsnUeScefPdnConnectionsInForwardRelocationRequestData const &data, Debug &stream)
{
    stream.incrIndent();
    stream.add((char *)"MmeSgsnUeScefPdnConnectionsInForwardRelocationRequest:");
    stream.endOfLine();
    stream.incrIndent();

    stream.add((char *)"apn:");
    stream.endOfLine();
    ApnIe apn=
    dynamic_cast<
    ApnIe&>(GtpV2IeFactory::getInstance().getIeObject(ApnIeType));
    apn.displayApnIe_v(data.apn, stream);

    stream.add((char *)"defaultEpsBearerId:");
    stream.endOfLine();
    EbiIe defaultEpsBearerId=
    dynamic_cast<
    EbiIe&>(GtpV2IeFactory::getInstance().getIeObject(EbiIeType));
    defaultEpsBearerId.displayEbiIe_v(data.defaultEpsBearerId, stream);

    stream.add((char *)"scefId:");
    stream.endOfLine();
    NodeIdentifierIe scefId=
    dynamic_cast<
    NodeIdentifierIe&>(GtpV2IeFactory::getInstance().getIeObject(NodeIdentifierIeType));
    scefId.displayNodeIdentifierIe_v(data.scefId, stream);


    stream.decrIndent();
    stream.decrIndent();
}



