##! Logs network connection events - WEL ID: Security - 5156

@load zeek-agent

module Agent_WELNetworkConn;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
	    ## General host data
		#ts:             time   &log;
		#host_ts:        time   &log;
		#host:           string &log;
		#hostname:       string &log;
		zeek_time:      int    &log;
        #date_time:     int    &log;

        ## System data
		#source:         string &log;
		#provider_name:  string &log;
		#provider_guid:  string &log;
		#computer_name:  string &log;
		#event_id:       int    &log;
		#task_id:        int    &log;
		#level:          int    &log;
		#pid:            int    &log;
		#tid:            int    &log;
		#keywords:       string    &log;
		#data:           string    &log;

		## Event data
		process_id:         int     &log;
		application:        string  &log;
		direction:          string  &log;
		source_address:     addr    &log &default=0.0.0.0;
		source_port:        int     &log;
		dest_address:       addr    &log &default=0.0.0.0;
		dest_port:          int     &log;
		protocol:           int     &log;
		filter_rtid:        int     &log;
		layer_name:         string  &log;
		layer_rtid:         int     &log;
		remote_user_id:     string  &log;
		remote_machine_id:  string  &log;
	};
}

event Agent_WELNetworkConn::network_conn(result: ZeekAgent::Result,
                                    zeek_time: int,
                                    #date_time: int,
                                    #source: string,
                                    #provider_name: string,
                                    #provider_guid: string,
                                    #computer_name: string,
                                    #event_id: int,
                                    #task_id: int,
                                    #level: int,
                                    #pid: int,
                                    #tid: int,
                                    #keywords: string,
                                    #data: string,
                                    process_id: int,
                                    application: string,
                                    direction: string,
                                    source_address: string,
                                    source_port: int,
                                    dest_address: string,
                                    dest_port: int,
                                    protocol: int,
                                    filter_rtid: int,
                                    layer_name: string,
                                    layer_rtid: int,
                                    remote_user_id: string,
                                    remote_machine_id: string)
	{
	if ( result$utype != ZeekAgent::ADD )
		return;

	#local host_ts = double_to_time(host_time);
	local info = Info($zeek_time = zeek_time,
	                  #$date_time = date_time,
	                  #$source = source,
	                  #$provider_name = provider_name,
	                  #$provider_guid = provider_guid,
	                  #$computer_name = computer_name,
	                  #$event_id = event_id,
	                  #$task_id = task_id,
	                  #$level = level,
	                  #$pid = pid,
	                  #$tid = tid,
	                  #$keywords = keywords,
	                  #$data = data,
	                  $process_id = process_id,
	                  $application = application,
	                  $direction = direction,
	                  $source_port = source_port,
	                  $dest_port = dest_port,
	                  $protocol = protocol,
	                  $filter_rtid = filter_rtid,
	                  $layer_name = layer_name,
	                  $layer_rtid = layer_rtid,
	                  $remote_user_id = remote_user_id,
	                  $remote_machine_id = remote_machine_id);

	if ( source_address != "" )
            info$source_address = to_addr(source_address);

    if ( dest_address != "" )
            info$dest_address = to_addr(dest_address);

	Log::write(LOG, info);
	}

event zeek_init() &priority=10
	{
	Log::create_stream(LOG, [$columns=Info, $path="agent-network_conn"]);

	local query = ZeekAgent::Query($ev=Agent_WELNetworkConn::network_conn,
	                                $query="SELECT zeek_time, process_id, application, direction, source_address, source_port, dest_address, dest_port, protocol, filter_rtid, layer_name, layer_rtid, remote_user_id, remote_machine_id FROM network_conn",
	                                $utype=ZeekAgent::ADD);
	ZeekAgent::subscribe(query);
	}
