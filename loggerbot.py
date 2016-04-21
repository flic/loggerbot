#! /usr/bin/env python
# -*- coding: utf-8 -*-

import time
from slackclient import SlackClient

import time
import re
from os import curdir, sep
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from SocketServer import ThreadingMixIn
#from urlparse import urlparse
import cgi
import simplejson as json
import threading
import fnmatch
from datetime import datetime,timedelta
import socket
import logging
import logging.handlers

# Slack
scToken = ""

# HTTP listener
bindPort = 9001
bindIP = "127.0.0.1"

alertQueue = []
alertPause = {}

helpText = "Things I understand: \n\npause <time>: _pause 15m_ - Temporarily pauses Logstash alerts\nresume: _resume_ - Resumes Logstash alerts\nstatus: _status_ - Shows paused channels"

#### Syslog ####

logger = logging.getLogger(socket.gethostname())
logger.setLevel(logging.INFO)

#add handler to the logger
handler = logging.handlers.SysLogHandler(address=('localhost',514))

#add formatter to the handler
formatter = logging.Formatter('%(asctime)s %(name)s %(module)s[%(process)s]: %(message)s', datefmt='%b %d %H:%M:%S')

handler.formatter = formatter
logger.addHandler(handler)

def log(severity,message):
    if severity == 'info':
       logger.info(message)
       print "INFO: "+message
    elif severity == 'error':
       logger.error(message)
       print "ERROR: "+message

#### HTTP Listener ####

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

class httpHandler(BaseHTTPRequestHandler):    
   def do_POST(self):
      global alertQueue

      log('info',"Received HTTP POST")
      self.send_response(200)
      self.end_headers()

      try:
         ctype, pdict = cgi.parse_header(self.headers.getheader('content-type'))
         uagent = str(self.headers.getheader('user-agent'))
         logger.info("HTTP User-agent: %s, Content-type: %s" % (uagent, ctype))
         data = self.rfile.read(int(self.headers['Content-Length']))
         data = data.decode('utf-8') 
         log('info',"HTTP POST (UTF-8 decoded):  "+data)
         if ctype == 'application/json': 
            p = json.loads(data)
            alertQueue.append(p)

      except Exception as e:
         log('error',"Exception: %s" % e)
         pass    


def httpListener(listenIP,listenPort):
   server = ThreadedHTTPServer((listenIP, listenPort), httpHandler)
   server.serve_forever()

#### Slack Alerts ####

def sendSlackAlert(strUser,strChannel,strAttachment):
   global sc
   response = sc.api_call('chat.postMessage',token=scToken,channel=strChannel,text='',username=strUser,attachments=strAttachment,as_user='false')
   if response['ok']:
      log('info',"Alert posted at: "+str(response['ts'])+" in channel "+ sc.server.channels.find(response['channel']).name)
   else:
      log('error',response['error'])
      log('error',response)
   return response
   
def createSlackAlertAttachment(strSourcehost,strSeverity,strSource,strMessage):
	if strSeverity == "error":
		strColor = "danger"
        elif strSeverity == "critical":
                strColor = "danger"
        elif strSeverity == "alert":
                strColor = "danger"
        elif strSeverity == "emergency":
                strColor = "danger"
	elif strSeverity == "warning":
		strColor = "warning"
	elif strSeverity == "info":
		strColor = "good"
        elif strSeverity == "notice":
                strColor = "good"
	else:
		strColor = "#439FE0"
		
	payload = json.dumps([{"fallback":"["+strSourcehost+"]["+strSeverity+"]","pretext": "*Source: "+strSource+"*","text":"```"+strMessage+"```","color":strColor,"mrkdwn_in": ["pretext","text"],"fields": [{"title":"Host","value":strSourcehost,"short":True},{"title":"Severity","value":strSeverity,"short":True}]}])
	return payload
      
def parseAlert(msg):
   if all(msg.has_key(name) for name in ('Channel','User','Sourcehost','Severity','Source','Message')):
      return True
   else:
      log('error',"parseHttpMessage: missing fields in message ("+str(msg)+")")
      return False
      
def slackAlert(msg):
   global alertPause
   if alertPause:
      log('info','Alerts paused, alert not sent to Slack')
   else:
      if parseAlert:
         attachment = createSlackAlertAttachment(msg['Sourcehost'],msg['Severity'],msg['Source'],msg['Message'])
         response = sendSlackAlert(msg['User'],msg['Channel'],attachment)

#### Slack Response ####

def sendSlackMessage(channel,message):
    global sc
    sc.rtm_send_message(channel,message)
    log('info',"Message posted in channel #"+sc.server.channels.find(channel).name)

#### Slack commands ####
def slackCmd_help(msg):
   sendSlackMessage(msg['channel'],helpText)

def slackCmd_pause(msg):
   global alertPause
   
   channel = sc.server.channels.find(msg['channel']).name
   match = re.search("[0-9]{1,4}[m|h]",msg['text'])
   if match:
      timeStr = match.group()
   else:
      timeStr = "3h"
   
   if (re.search('[0-9]{1,4}m',timeStr)):
      alertPause[channel] = datetime.now()+timedelta(minutes=int(timeStr.strip('m')))
   else:
      alertPause[channel] = datetime.now()+timedelta(hours=int(timeStr.strip('h')))
      
   sendSlackMessage(msg['channel'],"Pausing alerts in channel #"+channel+" until "+datetime.strftime(alertPause[channel],'%H:%M'))
   log('info',"Pausing alerts in channel #"+channel+" until "+datetime.strftime(alertPause[channel],'%H:%M'))

def slackCmd_resume(msg):
   global alertPause
   sendSlackMessage(msg['channel'],"Resuming alerts")
   log('info','Resuming alerts')
   if msg['channel'] in alertPause:
      del alertPause[msg['channel']]
      
def slackCmd_status(msg):      
   global alertPause
   
   message = '*Status*\n\n'
   if alertPause == {}:
      message += "No channels paused"
   else:
      for a in alertPause:
         message += "Channel #"+a+" paused until "+datetime.strftime(alertPause[a],'%H:%M')
   sendSlackMessage(msg['channel'],message)
   
#### Slack Events ####

def slackEvt_hello(msg):
   log('info',"Slack says hello")

def slackEvt_message(msg):
   slackCommand = {
      'help': slackCmd_help,
      'pause': slackCmd_pause,
      'shut up': slackCmd_pause,
      'resume': slackCmd_resume,
      'status': slackCmd_status,
   }

#   if (msg['channel'].startswith('D')) or (sc.server.channels.find(msg['channel']).name == alertChannel):

   msg['text'] = msg['text'].lower()
   for a in slackCommand.keys():
      match = re.search(a,msg['text'])
      if match:
         try:
            slackCommand[match.group()](msg)
         except Exception as e:
            print e
            pass
         
def parseSlackEvent(msg):
   slackEvent = {
      'hello': slackEvt_hello,
      'message': slackEvt_message,
   }

   if msg:
      try:
         slackEvent[msg[0]['type']](msg[0])
      except Exception as e:
         print str(e)
         pass

#### #### ####

def main():
   global sc
   global alertPause
   
   myThread = threading.Thread(target=httpListener, args=(bindIP,bindPort))
   myThread.daemon = True
   myThread.start()

   sc = SlackClient(scToken)
   if sc.rtm_connect():
      while True:
         for key, value in alertPause.items():
            if datetime.now() > value:
               sendSlackMessage(key,"Resuming alerts")
               log('info',"Resuming alerts in channel #"+key)
               del alertPause[key]
         parseSlackEvent(sc.rtm_read())
         if alertQueue:
            slackAlert(alertQueue.pop(0))
         time.sleep(1)
      else:
         log('error',"Connection Failed, invalid token?")

if __name__ == '__main__':
	main()


