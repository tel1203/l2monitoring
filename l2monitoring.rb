#
# sudo tcpdump -enw %Y%m%d-%H%M-multicast.dmp -s0 -W3 -G60 multicast
# tcpdump -lenr 20200314-154713-multicast.dmp 2>/dev/null | ruby l2monitoring.rb
#

def read_macaddrs(fname)
  f = open(fname, "r")
  names = Hash.new

  while (line = f.gets) do
    macaddr, name = line.chomp.split(" ")
    names[macaddr] = name
  end

  return (names)
end

name_macaddr = read_macaddrs("macaddrs.txt")

count_arp = Hash.new(0)
count_arp_all = 0
count_l2 = Hash.new(0)
count_l2_all = 0
count_ipv4 = Hash.new(0)
count_ipv4_all = 0
count_ipv6 = Hash.new(0)
count_ipv6_all = 0

macsaddrs = Hash.new(0)
ipv4saddrs = Hash.new(0)
ipv6saddrs = Hash.new(0)

line = STDIN.gets
time_begin = line.split(" ")[0]
time_end = ""
while (line = STDIN.gets) do
  time_end = line.split(" ")[0]

  /^.* length [0-9]*:/ =~ line
  l2head = $&.strip
  l3head = $'.strip

#  puts("---")
#  printf("%s\n", l2head)
#  printf("%s\n", l3head)

  data = l2head.split(",")
  smac = data[0].split(" ")[1]
  dmac = data[0].split(" ")[3]
  proto = data[1].strip
  length = data[2].match(/[0-9]+/)[0]

  macsaddrs[smac] += 1
  tmp = sprintf("%s -> %s", smac, dmac)
  count_l2[tmp] += 1
  count_l2_all += 1

  if (proto.index("ARP") != nil) then
    tmp = sprintf("%s -> %s", smac, dmac)
    count_arp[tmp] += 1
    count_arp_all += 1
  elsif (proto.index("IPv4") != nil) then
    addresses = l3head.split(":")
    tmp = addresses[0].split(" ")
    proto = addresses[1].split(" ")[0].strip

p l3head
#p addresses
#p tmp
#p proto
    sipaddr = tmp[0].split(".")[0,4].join(".")
    dipaddr = tmp[2].split(".")[0,4].join(".")
    dport   = tmp[2].split(".")[4]

p sipaddr
#p dipaddr
#p dport
    ipv4saddrs[sipaddr] += 1

    if (proto == "UDP,") then
      output = sprintf("%s(%s) -> %s:%s(%s)", sipaddr, smac, dipaddr, dport, dmac)
    elsif (proto == "0") then
      output = sprintf("%s(%s) -> %s:%s(%s)", sipaddr, smac, dipaddr, dport, dmac)
    elsif (proto == "igmp") then
      output = sprintf("%s(%s) -> %s:%s(%s)", sipaddr, smac, dipaddr, proto, dmac)
    end
 
    count_ipv4[output] += 1
    count_ipv4_all += 1
 
  else
#     p line
#    printf("%s %s %s %d\n", smac, dmac, proto, length)
#    p l3head
  end
end

p name_macaddr
# Output
printf("Statistics\n")
printf("%s %s\n", time_begin, time_end)
printf("- ARP (%d packets)\n", count_arp_all)
count_arp.each do |data|
  if (name_macaddr[data[0]] != nil) then
    printf("  %s(%s) : %d packets\n", data[0], name_macaddr[data[0]], data[1])
  else
    printf("  %s : %d packets\n", data[0], data[1])
  end
end

printf("- L2 (%d packets)\n", count_l2_all)
macsaddrs.sort.each do |data|
  if (name_macaddr[data[0]] != nil) then
    printf("  %s(%s) : %d packets\n", data[0], name_macaddr[data[0]], data[1])
  else
    printf("  %s : %d packets\n", data[0], data[1])
  end

  target = count_l2.keys.select do |x| x.include?(data[0]) end
  target.sort.each do |k|
    printf("    %s : %d packets\n", k, count_l2[k])
  end
end

printf("- IPv4 (%d packets)\n", count_ipv4_all)
ipv4saddrs.sort.each do |data|
  printf("  %s : %d packets\n", data[0], data[1])
  target = count_ipv4.keys.select do |x| x.include?(data[0]+"(") end

  target.sort.each do |k|
    printf("    %s : %d packets\n", k, count_ipv4[k])
  end
end

#count_ipv4.each do |data|
#  printf("  %s : %d packets\n", data[0], data[1])
#end
 
