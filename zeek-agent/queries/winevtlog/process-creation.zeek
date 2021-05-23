##! Logs process creation events - WEL ID: Security - 4688

@load zeek-agent

module Agent_WELProcessCreation;

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
		new_process_id:         string  &log;
		new_process_name:       string  &log;
		token_elevation_type:   string  &log;
		process_id:             string  &log;
		command_line:           string  &log;
		target_user_sid:        string  &log;
		target_user_name:       string  &log;
		target_logon_id:        string  &log;
		target_domain_name:     string  &log;
		parent_process_name:    string  &log;
		mandatory_label:        string  &log;
	};
}

event Agent_WELProcessCreation::process_creation(result: ZeekAgent::Result,
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
                                    new_process_id: string,
                                    new_process_name: string,
                                    token_elevation_type: string,
                                    process_id: string,
                                    command_line: string,
                                    target_user_sid: string,
                                    target_user_name: string,
                                    target_logon_id: string,
                                    target_domain_name: string,
                                    parent_process_name: string,
                                    mandatory_label: string)
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
	                  $new_process_id = new_process_id,
	                  $new_process_name = new_process_name,
	                  $token_elevation_type = token_elevation_type,
	                  $process_id = process_id,
	                  $command_line = command_line,
	                  $target_user_sid = target_user_sid,
	                  $target_user_name = target_user_name,
	                  $target_logon_id = target_logon_id,
	                  $target_domain_name = target_domain_name,
	                  $parent_process_name = parent_process_name,
	                  $mandatory_label = mandatory_label);

	Log::write(LOG, info);
	}

event zeek_init() &priority=10
	{
	Log::create_stream(LOG, [$columns=Info, $path="agent-process_creation"]);

	local query = ZeekAgent::Query($ev=Agent_WELProcessCreation::process_creation,
	                                $query="SELECT zeek_time, subject_user_id, subject_user_name, subject_domain_name, subject_logon_id, new_process_id, new_process_name, token_elevation_type, process_id, command_line, target_user_sid, target_user_name, target_logon_id, target_domain_name, parent_process_name, mandatory_label FROM process_creation",
	                                $utype=ZeekAgent::ADD);
	ZeekAgent::subscribe(query);
	}

