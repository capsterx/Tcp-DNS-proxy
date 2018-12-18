#!/usr/bin/env python
# -*- coding: utf-8 -*-
# cody by zhouzhenster@gmail.com

#
# Change log:
#
# 2011-10-23  use SocketServer to run a multithread udp server
# 2012-04-16  add more public dns servers support tcp dns query
# 2013-05-14  merge code from @linkerlin, add gevent support
# 2013-06-24  add lru cache support
# 2013-08-14  add option to disable cache
# 2014-01-04  add option "servers", "timeout" @jinxingxing
# 2014-04-04  support daemon process on unix like platform
# 2014-05-27  support udp dns server on non-standard port
# 2014-07-08  use json config file
# 2014-07-09  support private host
# 2015-01-14  support dns server auto switch

#  8.8.8.8        google
#  8.8.4.4        google
#  156.154.70.1   Dnsadvantage
#  156.154.71.1   Dnsadvantage
#  208.67.222.222 OpenDNS
#  208.67.220.220 OpenDNS
#  198.153.192.1  Norton
#  198.153.194.1  Norton

import gevent
import os
import socket
import struct
import SocketServer
import argparse
import json
import time
from fnmatch import fnmatch
import logging
import third_party
from pylru import lrucache
import ctypes
import sys

def hexdump(src, width=16):
    """ hexdump, default width 16
    """
    FILTER = ''.join(
        [(x < 0x7f and x > 0x1f) and chr(x) or '.' for x in range(256)])
    result = []
    for i in xrange(0, len(src), width):
        s = src[i:i + width]
        hexa = ' '.join(["%02X" % ord(x) for x in s])
        printable = s.translate(FILTER)
        result.append("%04X   %s   %s\n" % (i, hexa, printable))
    return ''.join(result)


def bytetodomain(s):
    """bytetodomain

    03www06google02cn00 => www.google.cn
    """
    domain = ''
    i = 0
    length = struct.unpack('!B', s[0:1])[0]

    while length != 0:
        i += 1
        domain += s[i:i + length]
        i += length
        length = struct.unpack('!B', s[i:i + 1])[0]
        if length != 0:
            domain += '.'

    return domain

cfg = {}

def cfg_logging(dbg_level):
    """ logging format
    """
    logging.basicConfig(format='[%(asctime)s][%(levelname)s] %(message)s',
                        level=dbg_level)


class TestSpeed:
  def __init__(self, servers):
    self.servers = servers

  def check_lag(self):
    logging.info('Testing dns server speed ...')
    jobs = []
    for i in xrange(0, 6):
        for s in servers:
            ip, port = s.split(':')
            jobs.append(gevent.spawn(dnsping, ip, port))
    
    return [thread.value for thread in gevent.joinall(jobs)]

  def dnsping(ip, port):
      buff =  "\x00\x1d\xb2\x5f\x01\x00\x00\x01"
      buff += "\x00\x00\x00\x00\x00\x00\x07\x74"
      buff += "\x77\x69\x74\x74\x65\x72\x03\x63"
      buff += "\x6f\x6d\x00\x00\x01\x00\x01"
  
      cost = 100
      begin = time.time()
      try:
          s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          s.settimeout(cfg['socket_timeout'])
          s.connect((ip, int(port)))
          s.send(buff)
          s.recv(2048)
      except Exception as e:
          logging.error('%s:%s, %s' % (ip, port, str(e)))
      else:
          cost = time.time() - begin
      return cost

class DNS_Server:
  def __init__(self, servers):
    self.servers = servers

  def query_server(self, server, port, querydata, use_udp=True):
      """dns request
  
      Args:
          server: remote tcp dns server
          port: remote tcp dns port
          querydata: udp dns request packet data
  
      Returns:
          dns response data
      """
  
      # length
      buf_len = struct.pack('!h', len(querydata))
      sendbuf = use_udp and querydata or buf_len + querydata
  
      try:
          protocol = use_udp and socket.SOCK_DGRAM or socket.SOCK_STREAM
          s = socket.socket(socket.AF_INET, protocol)
  
          # set socket timeout
          s.settimeout(cfg['socket_timeout'])
          s.connect((server, int(port)))
          s.send(sendbuf)
          data = s.recv(2048)
          return data
      finally:
          if s:
              s.close()

  def check_dns_packet(self, data, q_type, udp):
      test_ipv4 = False
      test_ipv6 = False
  
      if len(data) < 12:
          return False
  
      Flags = udp and data[2:4] or data[4:6]
  
      Reply_code = struct.unpack('>h', Flags)[0] & 0x000F
  
      # TODO: need more check
      if Reply_code == 3:
          return True
  
      if q_type == 0x0001:
  
          ipv4_len = data[-6:-4]
          ipv4_answer_class = data[-12:-10]
          ipv4_answer_type = data[-14:-12]
  
          test_ipv4 = (ipv4_len == '\x00\x04' and \
                       ipv4_answer_class == '\x00\x01' and \
                       ipv4_answer_type == '\x00\x01')
  
          if not test_ipv4:
  
              ipv6_len = data[-18:-16]
              ipv6_answer_class = data[-24:-22]
              ipv6_answer_type =data[-26:-24]
  
              test_ipv6 = (ipv6_len == '\x00\x10' and \
                           ipv6_answer_class == '\x00\x01' and \
                           ipv6_answer_type == '\x00\x1c')
  
          if not (test_ipv4 or test_ipv6):
              return False
  
      return Reply_code == 0

  def decode_query(self, data):
      q_domain = bytetodomain(data[12:-4])
      q_type = struct.unpack('!h', data[-4:-2])[0]
  
      logging.debug('domain:%s, qtype:%x' % (q_domain, q_type))
          
      return q_type, q_domain

  def construct_dns_response(self, data, ip):
    TID = data[0:2]
  
    Questions = data[4:6]
    AnswerRRs = data[6:8]
    AuthorityRRs = data[8:10]
    AdditionalRRs = data[10:12]
  
    q_type, q_domain = self.decode_query(data)

    if q_type != 0x0001:
        return
  
    if Questions != '\x00\x01' or AnswerRRs != '\x00\x00' or \
        AuthorityRRs != '\x00\x00' or AdditionalRRs != '\x00\x00':
            return
  
    ret = TID
    ret += '\x81\x80'
    ret += '\x00\x01'
    ret += '\x00\x01'
    ret += '\x00\x00'
    ret += '\x00\x00'
    ret += data[12:]
    ret += '\xc0\x0c'
    ret += '\x00\x01'
    ret += '\x00\x01'
    ret += '\x00\x00\xff\xff'
    ret += '\x00\x04'
    ret +=  socket.inet_aton(ip)
    return ret


  def transfer(self, querydata, addr, server):
      """send udp dns respones back to client program
  
      Args:
          querydata: udp dns request data
          addr: udp dns client address
          server: udp dns server socket
  
      Returns:
          None
      """
  
      if len(querydata) < 12:
          return
    
      q_type, q_domain = self.decode_query(querydata)
  
      t_id = querydata[:2]
      key = querydata[2:].encode('hex')
  
      for item in self.servers:
          for match in item['match']:
            if fnmatch(q_domain, match):
              if "resolve_to" in item:
                response = self.construct_dns_response(querydata, item['resolve_to'])
                if response:
                  server.sendto(response, addr)
                  break
              else:
                logging.debug("server: %s port:%s" % (item['host'], item['port']))
                response = self.query_server(item['host'], item['port'], querydata, item['udp'])
                if response is None or not self.check_dns_packet(response, q_type, item['udp']):
                    continue
                sendbuf = item['udp'] and response or response[2:]
                server.sendto(sendbuf, addr)
                break
          else:
              continue
          break
      else:
          logging.error('Tried many times and failed to resolve %s' % q_domain)


#def HideCMD():
#    whnd = ctypes.windll.kernel32.GetConsoleWindow()
#    if whnd != 0:
#        ctypes.windll.user32.ShowWindow(whnd, 0)
#        ctypes.windll.kernel32.CloseHandle(whnd)



class ThreadedUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
    def __init__(self, host, port, dns):
        SocketServer.UDPServer.__init__(self, (host, port), ThreadedUDPRequestHandler)
        self.dns = dns

class ThreadedUDPRequestHandler(SocketServer.BaseRequestHandler):
    # Ctrl-C will cleanly kill all spawned threads
    daemon_threads = True
    # much faster rebinding
    allow_reuse_address = True

    def handle(self):
        data = self.request[0]
        socket = self.request[1]
        addr = self.client_address
        self.server.dns.transfer(data, addr, socket)


def thread_main(cfg):
    dns = DNS_Server(cfg["dns"])
    server = ThreadedUDPServer(cfg["host"], cfg["port"], dns)
    server.serve_forever()
    server.shutdown()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='TCP DNS Proxy')
    parser.add_argument('-f', dest='config_json', type=argparse.FileType('r'),
            required=False, help='Json config file')
    parser.add_argument('-d', dest='dbg_level', action='store_true',
            required=False, default=False, help='Print debug message')
    parser.add_argument('-s', dest="stop_daemon", action='store_true',
            required=False, default=False, help='Stop tcp dns proxy daemon')
    args = parser.parse_args()

    if args.dbg_level:
        cfg_logging(logging.DEBUG)
    else:
        cfg_logging(logging.INFO)

    try:
        cfg = json.load(args.config_json)
    except Exception as e:
        print e
        logging.error('Loading json config file error [!!]')
        sys.exit(1)

    if not cfg.has_key("host"):
        cfg["host"] = "0.0.0.0"

    if not cfg.has_key("port"):
        cfg["port"] = 53

    logging.info('TCP DNS Proxy, https://github.com/henices/Tcp-DNS-proxy')
    logging.info('DNS Servers:\n%s' % cfg['dns'])
    logging.info('Query Timeout: %f' % (cfg['socket_timeout']))

    #if cfg['speed_test']:
    #    TestSpeed()

    logging.info(
            'Now you can set dns server to %s:%s' % (cfg["host"], cfg["port"]))

    thread_main(cfg)
