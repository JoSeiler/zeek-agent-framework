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
        ## win event specific
		source:         string &log;
		provider_name:  string &log;
		provider_guid:  string &log;
		computer_name:  string &log;
		event_id:       int    &log;
		task_id:        int    &log;
		level:          int    &log;
		pid:            int    &log;
		tid:            int    &log;
		keywords:       string    &log;
		data:           string    &log;
	};
}

event Agent_SocketOpen::socket_open(result: ZeekAgent::Result,
                                    source: string, provider_name: string, provider_guid: string,
                                    computer_name: string, event_id: int, task_id: int, level: int,
                                    pid: int, tid: int, keywords: string, data: string,
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
	                  $provider_name = provider_name,
	                  $provider_guid = provider_guid,
	                  $computer_name = computer_name,
	                  $event_id = event_id,
	                  $task_id = task_id,
	                  $level = level,
	                  $pid = pid,
	                  $tid = tid,
	                  $keywords = keywords,
	                  $data = data);

	Log::write(LOG, info);
	}

event zeek_init() &priority=10
	{
	Log::create_stream(LOG, [$columns=Info, $path="agent-sockets_opening"]);

	local query = ZeekAgent::Query($ev=Agent_SocketOpen::socket_open,
	                                $query="SELECT source, provider_name, provider_guid, computer_name, event_id, task_id, level, pid, tid, keywords, data FROM winsocket_events",
	                                $utype=ZeekAgent::ADD);
	ZeekAgent::subscribe(query);
	}
