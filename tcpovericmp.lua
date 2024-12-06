-- Define the protocol
my_protocol = Proto("TCPoverICMP", "TCP over ICMP Protocol")

-- Define the protocol fields
my_protocol.fields.icmp_type = ProtoField.uint8("tcpovericmp.icmp_type", "ICMP Type", base.DEC)
my_protocol.fields.icmp_code = ProtoField.uint8("tcpovericmp.icmp_code", "ICMP Code", base.DEC)
my_protocol.fields.icmp_checksum = ProtoField.uint16("tcpovericmp.icmp_checksum", "ICMP Checksum", base.HEX)
my_protocol.fields.icmp_id = ProtoField.uint16("tcpovericmp.icmp_id", "Identifier", base.DEC)
my_protocol.fields.icmp_seq = ProtoField.uint16("tcpovericmp.icmp_seq", "Sequence Number", base.DEC)
my_protocol.fields.local_ip = ProtoField.ipv4("tcpovericmp.local_ip", "Local IP")
my_protocol.fields.local_port = ProtoField.uint16("tcpovericmp.local_port", "Local Port", base.DEC)
my_protocol.fields.remote_ip = ProtoField.ipv4("tcpovericmp.remote_ip", "Remote IP")
my_protocol.fields.remote_port = ProtoField.uint16("tcpovericmp.remote_port", "Remote Port", base.DEC)
my_protocol.fields.payload = ProtoField.string("tcpovericmp.payload", "Payload")

-- Calculate ICMP checksum
local function calculate_checksum(buffer)
    local checksum = 0
    local length = buffer:len()
    local i = 0

    -- Sum up 16-bit words
    while i + 1 < length do
        local word = buffer(i, 2):uint()
        checksum = checksum + word
        checksum = (checksum & 0xFFFF) + (checksum >> 16) -- Handle overflow
        i = i + 2
    end

    -- Handle odd-length buffers
    if i < length then
        local last_byte = buffer(i, 1):uint()
        checksum = checksum + (last_byte << 8) -- Pad the last byte to form a 16-bit word
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    end

    checksum = ~checksum & 0xFFFF -- Final bitwise inversion
    return checksum
end

-- Dissector function
function my_protocol.dissector(buffer, pinfo, tree)
    -- Check minimum length (header + addresses/ports + payload)
    if buffer:len() < 20 then
        return  -- Exit if the packet is too short
    end

    -- Extract ICMP fields
    local icmp_type = buffer(0, 1):uint()
    local icmp_code = buffer(1, 1):uint()
    local icmp_checksum = buffer(2, 2):uint()
    local calculated_checksum = calculate_checksum(buffer)
    local checksum_valid = (calculated_checksum == 0)

    -- Update the protocol column in the packet list
    local icmp_message_type = "Unknown"
    if icmp_type == 8 then
        icmp_message_type= "Echo Request"
    elseif icmp_type == 0 then
        icmp_message_type = "Echo Reply"
    end
    pinfo.cols.protocol = string.format("TCPoverICMP (%s)", icmp_message_type)


    -- Update the Info column
    local seq = buffer(6, 2):uint()
    local id = buffer(4, 2):uint()

    local message_type = "Unknown"
    if id == 1 then
        message_type = "TCP Data"
    elseif id == 2 then
        message_type = "ACK"
    end

    pinfo.cols.info = string.format("%s, Seq: %d", message_type, seq)

    -- Create protocol subtree
    local subtree = tree:add(my_protocol, buffer(), "TCP over ICMP Data")

    -- Add ICMP fields
    subtree:add(my_protocol.fields.icmp_type, buffer(0, 1)):append_text(string.format(" (%s)",icmp_message_type))
    subtree:add(my_protocol.fields.icmp_code, buffer(1, 1))
    subtree:add(my_protocol.fields.icmp_checksum, buffer(2, 2)):append_text(checksum_valid and " (Checksum Validity: Valid)" or " (Checksum Validity: Invalid)")
    subtree:add(my_protocol.fields.icmp_id, buffer(4, 2)):append_text(string.format(" (%s)",message_type))
    subtree:add(my_protocol.fields.icmp_seq, buffer(6, 2))

    -- Add local IP and port
    subtree:add(my_protocol.fields.local_ip, buffer(8, 4))
    subtree:add(my_protocol.fields.local_port, buffer(12, 2))

    -- Add remote IP and port
    subtree:add(my_protocol.fields.remote_ip, buffer(14, 4))
    subtree:add(my_protocol.fields.remote_port, buffer(18, 2))

    -- Add payload if it exists
    if buffer:len() > 20 then
        subtree:add(my_protocol.fields.payload, buffer(20):string())
    end
end

-- Register the dissector
local ip_proto_table = DissectorTable.get("ip.proto")
ip_proto_table:add(1, my_protocol)  -- 1 is the protocol number for ICMP
