##! Logs network connection events - WEL ID: Security - 5156
## This event is generated when the Windows Filtering Platform has allowed a connection.

@load zeek-agent

module Agent_WELNetworkConn;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		#ts:             time   &log;
		#host_ts:        time   &log;
		#host:           string &log;
		#hostname:       string &log;
        ## win event specific
		zeek_time:      int    &log;
		#date_time:     int    &log;
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

event Agent_WELNetworkConn::network_conn(result: ZeekAgent::Result,
                                    zeek_time: int,
                                    #date_time: int,
                                    source: string,
                                    provider_name: string,
                                    provider_guid: string,
                                    computer_name: string,
                                    event_id: int,
                                    task_id: int,
                                    level: int,
                                    pid: int,
                                    tid: int,
                                    keywords: string,
                                    data: string)
	{
	if ( result$utype != ZeekAgent::ADD )
		return;

	#local host_ts = double_to_time(host_time);
	local info = Info($zeek_time = zeek_time,
	                  #$date_time = date_time,
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
	Log::create_stream(LOG, [$columns=Info, $path="agent-network_conn"]);

	local query = ZeekAgent::Query($ev=Agent_WELNetworkConn::network_conn,
	                                $query="SELECT zeek_time,
	                                source,
	                                provider_name,
	                                provider_guid,
	                                computer_name,
	                                event_id,
	                                task_id,
	                                level,
	                                pid,
	                                tid,
	                                keywords,
	                                data FROM winsocket_events",
	                                $utype=ZeekAgent::ADD);
	ZeekAgent::subscribe(query);
	}
