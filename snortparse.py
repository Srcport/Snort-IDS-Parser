import re 
import json
import os
import glob

class Parser(object):
    '''
    this will take an array of lines and parse it and hand back a dictionary
    '''
    def __init__(self):
        pass #gas
    
    def assemble(self,lines):
        buf = ''
        for line in lines:
            if line[-1:] == "\\":
                buf += line[:-1]
            else:
                buf+=line
        return buf
                            
    def parse(self,lines,fname):
		try:
			if type(lines) != list:
				raise Exception('Input is not an array of strings') 
			
			line = self.assemble(lines)        
			#the text up to the first ( is the rule header
			# the section encclosed in the () are the rule options    
			res = re.search(r'(^.+)\((.+)\)',line)
			#make dict
			header = res.groups(1)[0]
			option = res.groups(1)[1]      
			#process the header by splitting on space
			headers = header.split()
			rule = {
					'file':fname,
					'action':headers[0],
					'protocol':headers[1],
					'srcaddresses':headers[2],
					'srcports':headers[3],
					'direction':headers[4],
					'dstaddresses':headers[5],
					'dstports':headers[6],
					'activatedynamic':None                
					}
			#attribute/value pairs
			ruleOptions = {}
			options = option.split(";")
			for opt in options:
				try:
					kv = opt.split(":")
					ruleOptions[kv[0].strip()] = kv[1]
				except Exception:
					pass
			rule['options'] = ruleOptions        
			return rule
		except Exception:
			error = True
    
if __name__ == "__main__":
	p = Parser()   
    #rule = 'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"BLACKLIST User-Agent known malicious user agent Opera 10"; flow:to_server,established; content:"Opera/10|20|"; fast_pattern:only; http_header; metadata:impact_flag red, policy balanced-ips drop, policy security-ips drop, ruleset community, service http; reference:url,blog.avast.com/2013/05/03/regents-of-louisiana-spreading-s irefef-malware; reference:url,dev.opera.com/articles/view/opera-ua-string-changes; classtype:trojan-activity; sid:26577; rev:2;)'
    #rule = 'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE-CNC Win.Trojan.Travnet Botnet data upload"; flow:to_server,established; content:"hostid="; http_uri; content:"|26|hostname="; http_uri; content:"|26|hostip="; http_uri; metadata:policy balanced-ips drop, policy security-ips drop, ruleset community, service http; reference:url,www.virustotal.com/en/file/F7E9A1A4FC4766ABD799B517AD70CD5FA234C8ACC10D96CA51ECF9CF227B94E8/analysis/; classtype:trojan-activity; sid:26656; rev:1;)'
    #rule = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"OS-SOLARIS EXPLOIT sparc overflow attempt"; flow:to_server,established; content:"|90 1A C0 0F 90 02| |08 92 02| |0F D0 23 BF F8|"; fast_pattern:only; metadata:ruleset community, service dns; classtype:attempted-admin; sid:267; rev:13;)'
		
	for filename in glob.glob('C:/Users/Phil/Desktop/rules/*.rules'):
		with open(filename) as f:
			for line in f:
				if (line[0] != '#' and len(line) > 1):
					print (json.dumps(p.parse([line],os.path.basename(filename))))