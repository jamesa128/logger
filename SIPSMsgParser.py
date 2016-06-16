from LogParser import LogParser
import re, sys
from datetime import datetime
#from logger import submitter
import logging

class SIPSMsgParser(LogParser):
    # static vars

    # beginning of SIP message received by SIP Server
    # 16:45:03.031: SIPTR: Received [0,UDP] 467 bytes from 10.51.34.110:5060 <<<<<
    pattern_sip_msg_received = re.compile('^(\S+)(?::|) SIPTR: Received \[\S+\] \d+ bytes from (\S+) <<<<<$')
    # beggining of a SIP message sent by SIP Server
    # 16:45:04.720: Sending  [0,UDP] 406 bytes to 10.51.34.110:5060 >>>>>
    pattern_sip_msg_sent = re.compile('^(\S+)(?::|) Sending  \[\S+\] \d+ bytes to (\S+) >>>>>$')
    # Call-ID: ...
    pattern_sip_call_id = re.compile('Call-ID: (.+)$', re.IGNORECASE)
    # SIP-19501 [adjames] - Add pattern to determine SIP request for request and response
    # CSeq: 3 INVITE
    pattern_sip_request = re.compile('CSeq: (\d+) (\w+)$')
    # SIP-19501 [adjames] - Add pattern to read UUID marker from log
    # 16:28:01.319: CID:UUID>FF896752-F2E8-46A4-95C5-499BF2919C84-1@UTE_HOME:N4J2Q1678T29107HIBVLHE693G000001:
    # SIP-19501 [adjames] - Create tuple to allow us to determine which requests require UUID matching.
    call_request_tuple = ("INVITE","ACK","BYE","PRACK","NOTIFY","INFO","REFER")
    
    def __init__(self,submitter,tags={}):
        logging.debug("SIPSMsgParser __init__")
        LogParser.__init__(self, submitter,tags)
        # buffer
        self.sip_msg = ''
        # dictionary for SIP msg
        self.d_sip_msg = {}
        # bool we are in sip msg
        self.in_sip_msg = 0
        # SIP-19501 [adjames] - if set we are waiting for CID:UUID> line match before submitting message.
        self.in_uuid_match = 0
        
    def init_sip_message(self):
        if (self.in_uuid_match):
        self.in_sip_msg = 1
        self.sip_msg = ''
        #self.d_sip_msg.clear()
        self.d_sip_msg = self.d_common_tags.copy()
        self.in_uuid_match = 0
        return
    
    def submit_sip_message(self):
        #print "-- end of SIP msg"
        self.d_sip_msg['message'] = self.sip_msg
        self.submitter.d_submit(self.d_sip_msg,"SIP")        
        self.in_sip_msg = 0
        self.in_uuid_match = 0
        return
    
    def parse_line(self, line, claimed=False):
        if(claimed):
            if(self.in_sip_msg):
                self.submit_sip_message()
            return False
        # print line
        # are we in the part of the SIPS log that is a SIP Message?
        if(self.in_sip_msg):
            self.in_sip_msg += 1
            if(self.in_sip_msg == 2): # first line
                if(line[:7] == 'SIP/2.0'):
                    self.d_sip_msg['method'] = (line[8:].rstrip())[:4096]
                else:
                    self.d_sip_msg['method'] = ((line.split())[0])[:4096]    
            else:    
                # call id?
                if not 'call_id' in self.d_sip_msg.keys():
                    _re_call_id = self.pattern_sip_call_id.match(line)
                    if(_re_call_id):
                        self.d_sip_msg['call_id'] = (_re_call_id.group(1).rstrip())[:4096]
                # SIP-19501 [adjames] - Add pattern to determine SIP request for request and response
                if not 'request' in self.d_sip_msg.keys():
                    _re_request = self.pattern_sip_request.match(line)
                    if (_re_request):
                        self.d_sip_msg['request'] = (_re_request.group(2).rstrip())[:4096]
                # checking for the end, and sending
                if(self.match_time_stamp(line)):
                    # SIP-19501 [adjames] - For call based requests, keep parsing until UUID marker (or another sip message)
                    else:
                        self.submit_sip_message()
                    return self.parse_line(line)
                #else:

            self.sip_msg = self.sip_msg + line
            return True
        
        # we are not, looking for the beggining of the SIP Message  
        else:
            # scout for time stamps
            if(self.match_time_stamp(line)):
            #print "-- match?"
                self.re_line = self.pattern_sip_msg_received.match(line)
                if(self.re_line):
                    self.init_sip_message()
                    self.match_time_stamp(self.re_line.group(1))
                    #self.d_sip_msg['@datetimestr'] = self.re_line.group(1)
                    self.d_sip_msg['from'] = (self.re_line.group(2))[:4096]  
                    self.d_sip_msg['@timestamp'] = datetime(self.cur_date['y'],self.cur_date['m'],self.cur_date['d'],self.cur_time['h'],self.cur_time['m'],self.cur_time['s'],self.cur_time['ms'])
                else:
                    self.re_line = self.pattern_sip_msg_sent.match(line)
                    if(self.re_line):
                        self.init_sip_message()
                        self.match_time_stamp(self.re_line.group(1))
                        #self.d_sip_msg['@datetimestr'] = self.re_line.group(1)                    
                        self.d_sip_msg['to'] = (self.re_line.group(2))[:4096]
                        self.d_sip_msg['@timestamp'] = datetime(self.cur_date['y'],self.cur_date['m'],self.cur_date['d'],self.cur_time['h'],self.cur_time['m'],self.cur_time['s'],self.cur_time['ms'])

                    # SIP-19501 [adjames] - Look for matching CID:UUID marker to add uuid to this msg and submit. 
                    elif (self.in_uuid_match):
                        self.re_line = self.pattern_uuid_marker.search(line)
                        if (self.re_line):
                            self.submit_sip_message()    
#            if(self.pattern_std_msg.match(line)): 
#                self.submitter.submit(line)
                    
        return False

    def __del__(self):
        logging.debug("SIPSMsgParser __del__")
        if(self.in_sip_msg):
            self.submit_sip_message()
        LogParser.__del__(self)
        return