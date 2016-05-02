#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
from slackclient import SlackClient

import time
import re
import sys
import getopt
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

alertQueue = []
alertPause = {}

# Ping Slack at interval, max allowed missed pings before exiting
pingFreq = 5
missedPings = 3

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
   global debug
   
   if severity == 'info':
      logger.info(message)
      if debug:
         print("INFO: %s" % message)
   elif severity == 'error':
      logger.error(message)
      if debug:
         print("ERROR: %s" % message)
   elif severity == 'debug':
      logger.debug(message)
      if debug:
         print("DEBUG: %s" % message)

#### HTTP Listener ####

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
   address_family = socket.AF_INET6
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
   response = sc.api_call('chat.postMessage',channel=strChannel,text='',username=strUser,attachments=strAttachment,as_user='false')
   if response['ok']:
      log('info',"Alert posted at: "+str(response['ts'])+" in channel "+ sc.server.channels.find(response['channel']).name)
   else:
      log('error',response['error']+" (Details: "+str(response)+")")
   return response
   
def createSlackAlertAttachment(strSourcehost,strSeverity,strSource,strMessage):
   strSeverity = strSeverity.lower()
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
            
def slackAlert(msg):
   global alertPause
   if alertPause:
      log('info','Alerts paused in channel #%s, alert not sent to Slack' % msg['channel'])
   else:
      msg_lower = {}
      for key, value in msg.items():
         msg_lower[key.lower()] = value
         
      if all(msg_lower.has_key(name) for name in ('channel','user','host','severity','source','message')):
         attachment = createSlackAlertAttachment(msg_lower['host'],msg_lower['severity'],msg_lower['source'],msg_lower['message'])
         response = sendSlackAlert(msg_lower['user'],msg_lower['channel'],attachment)
      else:
         log('error',"parseHttpMessage: missing fields in message ("+str(msg)+")")

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
   channel = sc.server.channels.find(msg['channel']).name
   sendSlackMessage(channel,"Resuming alerts in channel #%s" % channel)
   log('info','Resuming alerts in channel #%s' % channel)
   if channel in alertPause:
      del alertPause[channel]
      
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

   msg['text'] = msg['text'].lower()
   for a in slackCommand.keys():
      match = re.search(a,msg['text'])
      if match:
         try:
            slackCommand[match.group()](msg)
         except Exception as e:
            log('error','Exception: %s' % str(e))
            pass
         
def slackEvt_pong(msg):
   global lastPong
   log('debug','Received Ping echo-return')
   lastPong = int(time.time())
   
def slackEvt_reconnect_url(msg):
   log('debug','Reconnect URL: %s' % msg['url'])

def slackEvt_presence_change(msg):
   log('debug','Presence change, user %s %s' % (msg['user'],msg['presence']))

## ## ##

def parseSlackEvent(msg):
   slackEvent = {
      'hello': slackEvt_hello,
      'message': slackEvt_message,
      'pong': slackEvt_pong,
      'reconnect_url': slackEvt_reconnect_url,
      'presence_change': slackEvt_presence_change,
   }

   if msg:
      try:
         slackEvent[msg[0]['type']](msg[0])
      except Exception as e:
         log('debug','Exception: %s Message: %s' % (str(e),msg))
         pass

#### #### ####

def main():
   global sc
   global alertPause
   global debug
   global lastPing
   global lastPong
   global pingFreq
   global missedPings
   
   debug = False
   
   # HTTP listener
   bindPort = 9001
   bindIP = "::"

   scToken = ''

   try:
      opts, args = getopt.getopt(sys.argv[1:],"",["token=","port=","debug"])
   except getopt.GetoptError:
      print 'loggerbot --token <Slack API token> --port <listen port> --debug'
      sys.exit(2)
	
   for opt, arg in opts:
      if opt == "--token":
         scToken = arg
      elif opt == "--port":
         bindPort = int(arg)
      elif opt == "--debug":
         debug = True

   if debug:
      logger.setLevel(logging.DEBUG)
   
   log('info','Bind HTTP IP %s:%s' % (bindIP, str(bindPort)))
   myThread = threading.Thread(target=httpListener, args=(bindIP,bindPort))
   myThread.daemon = True
   myThread.start()

   sc = SlackClient(scToken)
   if sc.rtm_connect():
      lastPong = lastPing = int(time.time())
      while True:
         now = int(time.time())
         if now > lastPing + pingFreq:
         	sc.server.ping()
         	lastPing = now
         for key, value in alertPause.items():
            if datetime.now() > value:
               sendSlackMessage(key,"Resuming alerts")
               log('info',"Resuming alerts in channel #"+key)
               del alertPause[key]
         parseSlackEvent(sc.rtm_read())
         if alertQueue:
            slackAlert(alertQueue.pop(0))
         if lastPong+pingFreq*missedPings < now:
            log('error','Lost contact with Slack, exiting')
            break;
         time.sleep(1)
   else:
      log('error',"Connection Failed, invalid token?")

if __name__ == '__main__':
	main()


