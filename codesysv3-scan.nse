local nmap = require('nmap')
local stdnse = require('stdnse')
local ipOps = require('ipOps')
local packet = require('packet')

TCP_MAGIC = 0xe8170100
DATAGRAM_LAYER_MAGIC = 0xc5
CODESYS_TCP_MIN_PORT = 11740
CODESYS_TCP_MAX_PORT = 11743
CODESYS_UDP_MIN_PORT = 1740
CODESYS_UDP_MAX_PORT = 1743
MAX_PDU_SIZE = 512

description = [[
 Temp
]]


portrule = function(host, port)
    return true
end

local function ip_to_binary(ip)
    local binary = 0
    for octet in string.gmatch(ip, "%d+") do
        binary = (binary << 8) | tonumber(octet)
    end
    return binary
end

local function ip_to_hex(ip)
    local o1,o2,o3,o4 = ip:match("(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)" )
    return string.format("%x", o4)
end

-- Function to perform bitwise right shift (bit rshift) on an integer value
local function bit_rshift(a, n)

    return math.floor(a / (2 ^ n))
end

local function bit_length(n)

    if n == 0 then
        return 0
    end

    local bits = 0
    local abs_n = math.abs(n)  

    while abs_n > 0 do
        abs_n = bit_rshift(abs_n, 1)
        bits = bits + 1
    end

    return bits
end
local function bitshift_left(value, shift)
    return value * (2 ^ shift)
end

local function bitnot(value)
    local num_bits = 32 
    local mask = (1 << num_bits) - 1 
    
    local result = mask ~ value  
    
    return result
end

local function bitand(a, b)
    local result = 0
    local bit = 1
    
    while a > 0 and b > 0 do
        if a % 2 == 1 and b % 2 == 1 then
            result = result + bit 
        end
        a = math.floor(a / 2)  
        b = math.floor(b / 2) 
        bit = bit * 2  
    end
    
    return result
end

local function bitor(a, b)
    local result = 0
    local bit = 1
    
    while a > 0 or b > 0 do
        if a % 2 == 1 or b % 2 == 1 then
            result = result + bit  
        end
        a = math.floor(a / 2)  
        b = math.floor(b / 2)  
        bit = bit * 2  
    end
    
    return result
end


local function get_codesys_full_address(src_ip, src_port)
    
    local tmp = string.format("%x", src_port - CODESYS_UDP_MIN_PORT)
    local ip = tostring(ip_to_hex(src_ip))
    if string.len(ip) < 2 then
        ip = "0" .. ip
    end
    tmp = "0" .. tmp .. ip
    return tmp --.. "0000"
    
end


local function get_codesys_relativ_address(src_ip, port, netmask)
    local netmask_n = bitnot(ip_to_binary(netmask))
    local address = bitand(netmask_n, ip_to_binary(src_ip))
    local port_index = port - CODESYS_UDP_MIN_PORT
    local temp = stdnse.tohex(bitor(address, bitshift_left(port_index, bit_length(address))))

    if string.len(temp) < 2 then
        temp = "0" .. temp
    end
    temp = String.rep("0", (temp:len() + 28)/2)%4)
    return temp
end

local function endian(hexstream, order)
    if order == 0 then
        return hexstream
    end
    local reversed = {}

    for i = #hexstream, 1, -2 do
        local byte_pair = string.sub(hexstream, i - 1, i)
        table.insert(reversed, byte_pair)
    end

    return table.concat(reversed)
end

--Removes null terminators for easier handling
local function filter_hex(hexstream)
    local filtered_bytes = {}
    
    for i = 1, #hexstream, 2 do
        local byte_pair = string.sub(hexstream, i, i + 1)
        local byte_value = tonumber(byte_pair, 16)
        if byte_value ~= 0 then
            local ascii_char = string.char(byte_value)
            table.insert(filtered_bytes, ascii_char)
        end
    end

    return table.concat(filtered_bytes)
end

local function split_at(input, delimiter)
    local parts = {}

    -- Iterate over each substring using string.gmatch with a pattern that matches the delimiter
    for part in (input .. delimiter):gmatch("(.-)" .. delimiter) do
        table.insert(parts, part)
    end

    return parts
end

local function codesysv3_translate(bytes)
    print(bytes)
    bytes = "80c200".. split_at(bytes, "80c200")[2]
    local pos = 0
    local output = stdnse.output_table()
    local byte_order = tonumber(string.sub(bytes, 21, 22),16)
    --sub command len 2
        local sub_command = tonumber(endian(string.sub(bytes, pos, pos+4), byte_order),16)
        pos = pos + 5
        local version = 0
        version = tonumber(endian(string.sub(bytes, pos, pos+3), byte_order),16)
        --ns_client_version
        pos = pos + 4
        local message_id = endian(string.sub(bytes, pos, pos+7),byte_order)
        -- message id 
        pos = pos + 8

        if (version == 0x103 or version == 0x400) and sub_command == 0xc280 then

            local max_channels = tonumber(endian(string.sub(bytes, pos, pos+3), byte_order),16)
            pos = pos + 4
            pos = pos + 4
            local node_name_pos = tonumber(endian(string.sub(bytes, 24, 24+3),byte_order),16) *2
            pos = pos + 4
            local node_name_len = tonumber(endian(string.sub(bytes, pos, pos+3),byte_order),16) * 4 + 4
            pos = pos + 4

            local device_name_len = tonumber(endian(string.sub(bytes, pos, pos+3),byte_order),16) * 4 + 4
            pos = pos + 4

            local vendor_name_len = tonumber(endian(string.sub(bytes, pos, pos+3),byte_order),16) * 4 + 4
            pos = pos + 4

            local ns_client_target_type = tonumber(endian(string.sub(bytes, pos, pos+7),byte_order),16)
            pos = pos + 8

            local ns_client_target_id = tonumber(endian(string.sub(bytes, pos, pos+7),byte_order),16)
            pos = pos + 8

            local firmware = string.format("V%d.%d.%d.%d",  tonumber(string.sub(bytes, pos+6, pos+7), 16),
                                                            tonumber(string.sub(bytes, pos+4, pos+5), 16),
                                                            tonumber(string.sub(bytes, pos+2, pos+3), 16),
                                                            tonumber(string.sub(bytes, pos, pos+1), 16))


            pos = pos + 9

            local serial_len = tonumber(endian(string.sub(bytes, pos, pos+1)),16) *4 +4
            pos = pos + 2

            pos = pos + 25 + node_name_pos

            local ns_client_node_name = filter_hex(string.sub(bytes, pos, pos+node_name_len))
            pos = pos + node_name_len

            local ns_client_device_name = filter_hex(string.sub(bytes, pos, pos+device_name_len))
            pos = pos + device_name_len  

            local ns_client_vendor_name = filter_hex(string.sub(bytes, pos, pos+vendor_name_len))
            pos = pos + vendor_name_len  

            local ns_client_serial = filter_hex(string.sub(bytes, pos, pos+serial_len))

                output.NS_Client_Analysis = {
                    {Device_Name = ns_client_device_name},
                    {Device_Vendor = ns_client_vendor_name},
                    {Node_Name = ns_client_node_name},
                    {Firmware = firmware},
                    {Serialnumber = ns_client_serial},
                    {Max_Channels = max_channels},
                    {Target_Type = ns_client_target_type},
                    {Target_ID = ns_client_target_id},
                    --{Subcmd = stdnse.tohex(sub_command)},
                    {NS_Client_Version = stdnse.tohex(version)},
                    {MessageID = message_id},
                }
        end
    return output
end

local function build_payload_full_address(src_ip, src_port)

    local address = get_codesys_full_address(src_ip, src_port)

    return stdnse.fromhex("c57440030010ce6d" .. address .."000002c20004b4840000")
end


local function build_payload_relative_address(src_ip, src_port, netmask)

    local address = get_codesys_relativ_address(src_ip, src_port, netmask)
    return stdnse.fromhex("c56b30030010" .. address .."02c2000400000000")
end

local function distribute_payload(host, src_ip, src_port, payload)

    local socket = nmap.new_socket()
    socket:set_timeout(2500)
    socket:bind(nil, src_port)
    

    for i=1740, 1743, 1 do
        socket:connect(host.ip, i, "udp")
        socket:sendto(host.ip, i, payload)
        local status,data = socket:receive_bytes(1)
        print(data)
        if data ~= "TIMEOUT" and data ~= "ERROR" then
            local output = codesysv3_translate(stdnse.tohex(data))
            socket:close()
            return output
        end
        socket:close()

    end

end

action = function(host, port)
    local interface = host.interface or stdnse.get_script_args("interface")
    local info = nmap.get_interface_info(interface)
    local src_ip = info.address
    local netmask =  ipOps.cidr_to_subnet("/"..info.netmask)
    local src_port = 1740

    local payload = build_payload_full_address(src_ip, src_port)

    if stdnse.get_script_args("relative") == "test" then
        payload = build_payload_relative_address(src_ip, src_port, netmask)
    end

    return distribute_payload(host, src_ip, src_port, payload)

end