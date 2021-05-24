##! Logs registry value modification events - WEL ID: Security - 4657

@load zeek-agent

module Agent_WELRegvalModified;

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
		subject_user_id:        string  &log;
		subject_user_name:      string  &log;
		subject_domain_name:    string  &log;
		subject_logon_id:       string  &log;
		object_name:            string  &log;
		object_value_name:      string  &log;
		handle_id:              string  &log;
		operation_type:         string  &log;
		old_value_type:         string  &log;
		old_value:              string  &log;
		new_value_type:         string  &log;
		new_value:              string  &log;
		process_id:             string  &log;
		process_name:           string  &log;
	};
}

event Agent_WELRegvalModified::regval_modified(result: ZeekAgent::Result,
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
                                    subject_user_id: string,
                                    subject_user_name: string,
                                    subject_domain_name: string,
                                    subject_logon_id: string,
                                    object_name: string,
                                    object_value_name: string,
                                    handle_id: string,
                                    operation_type: string,
                                    old_value_type: string,
                                    old_value: string,
                                    new_value_type: string,
                                    new_value: string,
                                    process_id: string,
                                    process_name: string)
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
	                  $subject_user_id = subject_user_id,
	                  $subject_user_name = subject_user_name,
	                  $subject_domain_name = subject_domain_name,
	                  $subject_logon_id = subject_logon_id,
	                  $object_name = object_name,
	                  $object_value_name = object_value_name,
	                  $handle_id = handle_id,
	                  $operation_type = operation_type,
	                  $old_value_type = old_value_type,
	                  $old_value = old_value,
	                  $new_value_type = new_value_type,
	                  $new_value = new_value,
	                  $process_id = process_id,
	                  $process_name = process_name);

	Log::write(LOG, info);
	}

event zeek_init() &priority=10
	{
	Log::create_stream(LOG, [$columns=Info, $path="agent-regval_modified"]);

	local query = ZeekAgent::Query($ev=Agent_WELRegvalModified::regval_modified,
	                                $query="SELECT subject_user_id, subject_user_name, subject_domain_name, subject_logon_id, object_name, object_value_name, handle_id, operation_type, old_value_type, old_value, new_value_type, new_value, process_id, process_name FROM regval_modified",
	                                $utype=ZeekAgent::ADD);
	ZeekAgent::subscribe(query);
	}
