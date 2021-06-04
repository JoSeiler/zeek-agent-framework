##! Logs successful account logon events - WEL ID: Security - 4624

@load zeek-agent

module Agent_WELAccountLogon;

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
		subject_user_id:                string  &log;
		subject_user_name:              string  &log;
		subject_domain_name:            string  &log;
		subject_logon_id:               string  &log;
		target_user_sid:                string  &log;
		target_user_name:               string  &log;
		target_domain_name:             string  &log;
		target_logon_id:                string  &log;
		logon_type:                     int     &log;
		logon_process_name:             string  &log;
		authentication_package_name:    string  &log;
		workstation_name:               string  &log;
		logon_guid:                     string  &log;
		transmitted_services:           string  &log;
		lm_package_name:                string  &log;
		key_length:                     int     &log;
		process_id:                     string  &log;
		process_name:                   string  &log;
		ip_address:                     addr    &log &default=0.0.0.0;
		ip_port:                        int     &log;
		impersonation_level:            string  &log;
		restricted_admin_mode:          string  &log;
		target_outbound_user_name:      string  &log;
		target_outbound_domain_name:    string  &log;
		virtual_account:                string  &log;
		target_linked_logon_id:         string  &log;
		elevated_token:                 string  &log;
	};
}

event Agent_WELAccountLogon::account_logon(result: ZeekAgent::Result,
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
                                    target_user_sid: string,
                                    target_user_name: string,
                                    target_domain_name: string,
                                    target_logon_id: string,
                                    logon_type: int,
                                    logon_process_name: string,
                                    authentication_package_name: string,
                                    workstation_name: string,
                                    logon_guid: string,
                                    transmitted_services: string,
                                    lm_package_name: string,
                                    key_length: int,
                                    process_id: string,
                                    process_name: string,
                                    ip_address: string,
                                    ip_port: int,
                                    impersonation_level: string,
                                    restricted_admin_mode: string,
                                    target_outbound_user_name: string,
                                    target_outbound_domain_name: string,
                                    virtual_account: string,
                                    target_linked_logon_id: string,
                                    elevated_token: string)
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
	                  $target_user_sid = target_user_sid,
	                  $target_user_name = target_user_name,
                      $target_domain_name = target_domain_name,
                      $target_logon_id = target_logon_id,
                      $logon_type = logon_type,
                      $logon_process_name = logon_process_name,
                      $authentication_package_name = authentication_package_name,
                      $workstation_name = workstation_name,
                      $logon_guid = logon_guid,
                      $transmitted_services = transmitted_services,
                      $lm_package_name = lm_package_name,
                      $key_length = key_length,
                      $process_id = process_id,
                      $process_name = process_name,
                      $ip_port = ip_port,
                      $impersonation_level = impersonation_level,
                      $restricted_admin_mode = restricted_admin_mode,
                      $target_outbound_user_name = target_outbound_user_name,
                      $target_outbound_domain_name = target_outbound_domain_name,
                      $virtual_account = virtual_account,
                      $target_linked_logon_id = target_linked_logon_id,
                      $elevated_token = elevated_token);

    if ( ip_address != "" && ip_address != "-" )
                info$ip_address = to_addr(ip_address);


	Log::write(LOG, info);
	}

event zeek_init() &priority=10
	{
	Log::create_stream(LOG, [$columns=Info, $path="agent-account_logon"]);

	local query = ZeekAgent::Query($ev=Agent_WELAccountLogon::account_logon,
	                                $query="SELECT zeek_time, subject_user_id, subject_user_name, subject_domain_name, subject_logon_id, target_user_sid, target_user_name, target_domain_name, target_logon_id, logon_type, logon_process_name, authentication_package_name, workstation_name, logon_guid, transmitted_services, lm_package_name, key_length, process_id, process_name, ip_address, ip_port, impersonation_level, restricted_admin_mode, target_outbound_user_name, target_outbound_domain_name, virtual_account, target_linked_logon_id, elevated_token FROM account_logon",
	                                $utype=ZeekAgent::ADD);
	ZeekAgent::subscribe(query);
	}

