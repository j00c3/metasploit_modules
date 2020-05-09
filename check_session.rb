##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Existing C2 Connection Checker',
      'Description'   => %q{ Checks to see if target host already has an existing connection to C2 server, based on IP address and port. If so, new Meterpreter session exits. },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'j00c3'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptString.new('C2_RHOST', [ true, 'The C2 host/firewall/redirector IP address', '']),
        OptString.new('C2_RPORT', [ true, 'The C2 host/firewall/redirector port', ''])
      ], self.class)
  end

  # Run Method for when "run" command is issued
  def run
    begin
      c2_host = datastore['C2_RHOST']
      c2_port = datastore['C2_RPORT']
      local_connections = get_connections(c2_host, c2_port)

      local_connections.each do |i|
        puts i.local_addr, i.local_port
      end

      if local_connections.size > 2
        print_good "Existing C2 connection found! Exiting..."
        print_status "Existing C2 connection PID/process name: #{local_connections[0].pid_name}"
        session.run_cmd('exit')
      else
        print_good "No existing C2 connection found. New session will be maintained."
      end
    end
    
  end

  def get_connections(c2_host, c2_port)
    connections = client.net.config.netstat
    connection_local_ip_addrs = []

    connections.each do |connection|
      connection_local_ip_addrs << connection if connection.protocol == 'tcp' and (connection.remote_addr == c2_host and connection.remote_port == c2_port.to_i and connection.state == "ESTABLISHED")
    end
    
    puts connection_local_ip_addrs.size
    return connection_local_ip_addrs
  end
end