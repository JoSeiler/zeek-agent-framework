##! Logs object access attempts events - WEL ID: Security - 4663

@load zeek-agent

module Agent_WELObjAccessAttempt;

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
		object_server:          string  &log;
		object_type:            string  &log;
		object_name:            string  &log;
		handle_id:              string  &log;
		access_list:            string  &log;
		access_mask:            string  &log;
		process_id:             string  &log;
		process_name:           string  &log;
		resource_attributes:    string  &log;
	};
}

event Agent_WELObjAccessAttempt::objaccess_attempt(result: ZeekAgent::Result,
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
                                    object_server: string,
                                    object_type: string,
                                    object_name: string,
                                    handle_id: string,
                                    access_list: string,
                                    access_mask: string,
                                    process_id: string,
                                    process_name: string,
                                    resource_attributes: string)
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
	                  $object_server = object_server,
	                  $object_type = object_type,
	                  $object_name = object_name,
	                  $handle_id = handle_id,
	                  $access_list = access_list,
	                  $access_mask = access_mask,
	                  $process_id = process_id,
	                  $process_name = process_name,
	                  $resource_attributes = resource_attributes);

	Log::write(LOG, info);
	}

event zeek_init() &priority=10
	{
	Log::create_stream(LOG, [$columns=Info, $path="agent-obj_access_attempt"]);

	local query = ZeekAgent::Query($ev=Agent_WELObjAccessAttempt::objaccess_attempt,
	                                $query="SELECT zeek_time, subject_user_id, subject_user_name, subject_domain_name, subject_logon_id, object_server, object_type, object_name, handle_id, access_list, access_mask, process_id, process_name, resource_attributes FROM obj_access_attempt",
	                                $utype=ZeekAgent::ADD);
	ZeekAgent::subscribe(query);
	}
