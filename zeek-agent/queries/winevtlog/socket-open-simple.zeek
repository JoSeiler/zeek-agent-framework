##! Logs socket events activity

@load zeek-agent

module Agent_SocketOpen;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:             time   &log;
		host_ts:        time   &log;
		host:           string &log;
		hostname:       string &log;
		## Winevtlog specific
		source: string &log &optional;
		event_id: int &log &optional;
	};
}

event Agent_SocketOpen::socket_open(result: ZeekAgent::Result,
                                    source: string, event_id: int,
                                    host_time: int)
	{
	if ( result$utype != ZeekAgent::ADD )
		return;

	local host_ts = double_to_time(host_time);
	local info = Info($ts = network_time(),
	                  $host_ts = host_ts,
	                  $host = result$host,
	                  $hostname = ZeekAgent::getHostInfo(result$host)$hostname,
	                  $source = source,
	                  $event_id = event_id);

	Log::write(LOG, info);
	}

event zeek_init() &priority=10
	{
	Log::create_stream(LOG, [$columns=Info, $path="agent-sockets_opening"]);

	local query = ZeekAgent::Query($ev=Agent_SocketOpen::socket_open,
	                                $query="SELECT source, event_id FROM winsocket_events",
	                                $utype=ZeekAgent::ADD);
	ZeekAgent::subscribe(query);
	}