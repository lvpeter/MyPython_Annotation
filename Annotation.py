import asyncio
import re
import threading
import time
import warnings
import socket
import traceback
import sys
import os
import io

from http import server, HTTPStatus, cookies
from urllib import parse,request,response

"""
  os File
"""


class File:
    def __init__(self):
        self._format_Type: dict = None
        self._prepare()

    def _prepare(self):
        self._format_Type = {}
        self._format_Type["html"] = "text/html"
        self._format_Type["css"] = "text/css"
        self._format_Type["js"] = "application/x-javascript"
        self._format_Type["jpg"] = "image/jpeg"
        self._format_Type["png"] = "image/png"
        self._format_Type["json"] = "application/json"
        self._format_Type["xml"] = "text/xml"
        self._format_Type["apk"] = "application/vnd.android.package-archive"
        self._format_Type["ipa"] = "application/vnd.iphone"
        self._format_Type["xsl"] = "text/xml"
        self._format_Type["xslt"] = "text/xml"
        self._format_Type["txt"] = "text/plain"

    def __del__(self):
        del self._format_Type

    def content_type(self, name: str):
        if self._format_Type is None:
            self._prepare()
        else:

            result = self._format_Type.get(name.lower())
            if result is None:
                return "application/octet-stream"
            else:
                return result

"""
    Request And Response
"""
class Request:
    def __init__(self):
        self.responseDict:dict={}

    def request(self,
                url:str,
                body=None,
                Method:str="GET",
                headers:dict=None,
                timeout:int=5,
                proxy:str=None):

        return self.__Request(
            **{"url": url, "body": body,
             "Method": Method, "headers": headers,
             "timeout": timeout, "proxy": proxy}
        )
    def req(self,
            url: str,
            body=None,
            Method: str = "GET",
            headers: dict = None,
            timeout: int = 5,
            proxy: str = None,
            **kwargs):
        def func(f):
            if f.__code__.co_argcount <1:
                       warnings.warn(str(f.__name__)+"的参数少于1")
                       return f

            self.responseDict[f.__name__]={"func":f,"url":url,"body":body,
                                           "Method":Method,"headers":headers,
                                           "timeout":timeout,"proxy":proxy,"kwargs":kwargs}

            res=self.__Request(**self.responseDict[f.__name__])
            if res is None:
                f(None,**kwargs)
            else:
                res["name"]=f.__name__
                f(res,**kwargs)
            return f
        return func
    def xreq(self,
              name,
             **kwargs
              ):
        if isinstance(name,dict):
              name=name["name"]
        elif  not isinstance(name,str):
              name=name.__name__
        if self.responseDict.get(name)    is None:
               warnings.warn("无"+name+"这个方法")
               return
        for k in kwargs:
            self.responseDict[name][k]=kwargs[k]
        self.responseDict[name]["func"](self.__Request(**self.responseDict[name]), **self.responseDict[name]["kwargs"])

    def __Request(  self,
                   **kwargs
                   ):
        headers = {}
        headers["accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"
        headers["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.81 Safari/537.36"
        headers["accept-language"] = "zh-CN,zh;q=0.9"
        if not kwargs.get("headers") is None:
            for k in kwargs.get("headers"):
                headers[k]=kwargs[k]
        if  not kwargs["body"] is None and str(kwargs["Method"]).upper()=="GET":
                warnings.warn("body 不是None 而且 Type是GET ，自动转换POST")
                kwargs["Method"]="POST"
        requrl= request.Request(url=kwargs["url"],data=kwargs["body"],headers=headers,method=kwargs["Method"])
        res=None
        if not kwargs["proxy"] is None:
                res = request.urlopen(requrl,timeout=kwargs["timeout"])

        else:
                 res = request.build_opener(request.ProxyHandler(kwargs["proxy"])).open(requrl,timeout=kwargs["timeout"])

        if  res is None:
            return  None
        else:
            return {"URL":res.geturl(),"code":res.getcode(),"info":res.info(),"body":res.read()}




"""
  http web servlce
"""


class _Global_Web():
    def __init__(self, Object, Method, path):
        self.Object = Object
        self.Method: str = Method
        self.path: str = path


class _Request(_Global_Web):
    def __init__(self, Object, Method, path):
        super().__init__(Object, Method, path)
        self.request = self.Object.request
        self.rbufsize: int = self.Object.rbufsize
        self.requestline = self.Object.requestline
        self.headers: dict = self.Object.headers
        self.URL:str=self.headers["Host"]
        self.cookies: dict = self.str_To_cookie(self.headers["cookie"])

        if self.headers.get('Content-Length') is None:
            self.body: bytes = self.Object.rfile
        else:
            self.body: bytes = self.Object.rfile.read(int(self.headers.get('Content-Length')))

    @staticmethod
    def str_To_cookie(val: str):
        now = {}
        for v in val.split(";"):
            now[v.split("=")[0]] = v.split("=")[1]
        return now


class _Response:
    def __init__(self, S: _Global_Web):
        self. __GMT_FORMAT = '%a, %d %b %Y %H:%M:%S GMT'
        self.Object = S.Object
        self.timeout = S.Object.timeout
        self.status: int = 200
        self.headers: dict = {}
        self.cookies: dict = {}
        self.__set_simplecookie=cookies.SimpleCookie()
        self.__add_simplecookie = cookies.SimpleCookie()
        self.Write: bytes = None
    def __del__(self):
        del self.headers
        del self.cookies
        self.__set_simplecookie.clear()
        self.__add_simplecookie.clear()
    def ToHeaders(self,NewHeaders):
        self.Object.send_response(self.status)

        if NewHeaders.get("content-length") is None:
             if not self.Write is None:
                 NewHeaders["content-length"] = len(self.Write)
        for n in NewHeaders:
             self.Object.send_header(n, NewHeaders[n])
        if len(self.__add_simplecookie) != 0:
            self.Object.send_header("Cookie",self.__add_simplecookie.output()[len("Cookie:"):])
        if len(self.__set_simplecookie) != 0:
            self.Object.send_header("Set-Cookie",self.__set_simplecookie.output()[len("Set-Cookie:"):])

        self.Object.end_headers()
    def setCookie(self,
                  name: str,
                  value: str,
                  comment:str=None,
                  domain: str = None,
                  path: str = "/",
                  MaxAge: int = 0,
                  expires: int = None,
                  HttpOnly: bool = True,
                  secure: str = None,
                  version: int = None
                  ):
        """
        name:一个唯一确定的cookie名称。通常来讲cookie的名称是不区分大小写的。
        value:存储在cookie中的字符串值。最好为cookie的name和value进行url编码
        domain:cookie对于哪个域是有效的。所有向该域发送的请求中都会包含这个cookie信息。这个值可以包含子域(如：yq.aliyun.com)，也可以不包含它(如：.aliyun.com，则对于aliyun.com的所有子域都有效).
        path: 表示这个cookie影响到的路径，浏览器跟会根据这项配置，像指定域中匹配的路径发送cookie。
        expires:失效时间，表示cookie何时应该被删除的时间戳(也就是，何时应该停止向服务器发送这个cookie)。如果不设置这个时间戳，浏览器会在页面关闭时即将删除所有cookie；不过也可以自己设置删除时间。这个值是GMT时间格式，如果客户端和服务器端时间不一致，使用expires就会存在偏差。
        max-age: 与expires作用相同，用来告诉浏览器此cookie多久过期（单位是秒），而不是一个固定的时间点。正常情况下，max-age的优先级高于expires。
        HttpOnly: 告知浏览器不允许通过脚本document.cookie去更改这个值，同样这个值在document.cookie中也不可见。但在http请求张仍然会携带这个cookie。注意这个值虽然在脚本中不可获取，但仍然在浏览器安装目录中以文件形式存在。这项设置通常在服务器端设置。
        secure: 安全标志，指定后，只有在使用SSL链接时候才能发送到服务器，如果是http链接则不会传递该信息。就算设置了secure 属性也并不代表他人不能看到你机器本地保存的 cookie 信息，所以不要把重要信息放cookie就对了
        """
        self.__set_simplecookie[name] = value
        if not comment is None:
            self.__set_simplecookie[name]["comment"] = comment
        if domain is None:

            self.__set_simplecookie[name]["domain"] = self.Object.headers["Host"]
        else:
            self.__set_simplecookie[name]["domain"] = domain
        self.__set_simplecookie[name]["path"] = path

        if not expires is None:
            self.__set_simplecookie[name]["expires"] = time.strftime(self.__GMT_FORMAT, time.localtime(expires))
        else:
            self.__set_simplecookie[name]["expires"] = time.strftime(self.__GMT_FORMAT, time.localtime(
                time.time() + 1000 * 60 * 60 * 24 * 30))

        if MaxAge != 0:
            self.__set_simplecookie[name]["max-age"] = MaxAge
        if HttpOnly:
            self.__set_simplecookie[name]["HttpOnly"] = "HttpOnly"

        if not secure is None:
            self.__set_simplecookie[name]["secure"] = secure

        if not version is None:
            self.__set_simplecookie[name]["version"] = version

    def addCookie(self, name: str,
                  value: str,
                  domain: str = None,
                  path: str = "/",
                  comment:str=None,
                  expires:int=None,
                  MaxAge: str = "",
                  HttpOnly: bool = False,
                  secure: str = None,
                  version:int=None
                  ):
        self.__add_simplecookie[name] = value
        if not comment is None:
            self.__add_simplecookie[name]["comment"] = comment
        if domain is None:

            self.__add_simplecookie[name]["domain"] = self.Object.headers["Host"]
        else:
            self.__add_simplecookie[name]["domain"] = domain
        self.__add_simplecookie[name]["path"] = path

        if not expires is None:
            self.__add_simplecookie[name]["expires"] = time.strftime(self.__GMT_FORMAT, time.localtime(expires))
        else:
            self.__add_simplecookie[name]["expires"] = time.strftime(self.__GMT_FORMAT, time.localtime(time.time()+1000*60*60*24*30))

        if MaxAge != 0:
            self.__add_simplecookie[name]["max-age"] = MaxAge
        if HttpOnly:
            self.__add_simplecookie[name]["HttpOnly"] = "HttpOnly"

        if not secure is None:
            self.__add_simplecookie[name]["secure"] = secure

        if not version is None:
            self.__add_simplecookie[name]["version"] = version

    def removeCookie(self, name: str):
        if  not self.__add_simplecookie.get(name) is None:
               del self.__add_simplecookie[name]
        if not self.__set_simplecookie.get(name) is None:
            del self.__set_simplecookie[name]

class _baseWebCalss(server.BaseHTTPRequestHandler):

    def do_GET(self):

        if not globals().get("__Web_Servlce_hleper__") is None:
            globals()["__Web_Servlce_hleper__"](_Request(self, "GET", parse.unquote(self.path)))

    def do_POST(self):

        if not globals().get("__Web_Servlce_hleper__") is None:
            globals()["__Web_Servlce_hleper__"](_Request(self, "POST", parse.unquote(self.path)))


class WebServlce:
    def __init__(self, host: str = None, port: int = None):
        if not globals().get("__Web_Servlce_hleper__") is None:
            warnings.warn("路由已经开启，新路由覆盖旧的")
        self.__File_Type = File()
        self.encoding = "UTF-8"
        self.__host = host
        self.__port = port
        self.__err: dict = None
        self.server: server.HTTPServer = None
        self.__routeMap: dict = {}
        if not (self.__host is None and self.__port is None):
            self.__prepare()

    def __prepare_run(self):
        assert not self.server is None, " self.server is None"
        self.server.serve_forever()

    def __prepare(self):
        globals()["__Web_Servlce_hleper__"] = self.__handle_route
        self.server = server.HTTPServer((self.__host, self.__port), _baseWebCalss)
        _Thread_GO(func=self.__prepare_run, err=self.__err).start()

    def start(self, host: str = None, port: int = None):
        if not host is None:
            self.__host = host
        if not port is None:
            self.__port = port
        if not (self.__host is None and self.__port is None):
            if self.server is None:
                self.__prepare()

        else:
            warnings.warn("host port err no run server")

    def __handle_route(self, R: _Request):
        # 处理器
        try:
            P = _Response(R)
            for v in self.__routeMap:
                if not re.compile("^/?" + v + "($|\?)").match(R.path) is None:
                    result = self.__routeMap[v]["func"](R, P)
                    funcname = str(self.__routeMap[v]["func"].__name__)
                    NewHeaders = {}
                    for h in P.headers:
                        NewHeaders[str(h).lower()] = P.headers[h]

                    if not result is None:
                        if self.__routeMap[v]["Type"] == "static":
                            if isinstance(result, str):
                                fileBy: io.BytesIO = io.BytesIO()
                                if not P.Write is None:
                                    warnings.warn(funcname + "原本响应已经存在数据 方法又返回数据 进行数据拼接")
                                    fileBy.write(P.Write)
                                if os.path.exists(result):
                                    r = open(result, "rb+")
                                    fileBy.write(r.read())
                                    r.close()


                                else:
                                    filepath = os.getcwd()
                                    if result[0] != "\\" and result[0] != "/":
                                        filepath += "\\" + result
                                    if os.path.exists(filepath):
                                        r = open(filepath, "rb+")
                                        fileBy.write(r.read())
                                        r.close()
                                    else:
                                        raise OSError("没找到文件")

                                P.Write = fileBy.getvalue()
                                fileBy.close()
                                if NewHeaders.get("content-type") is None:
                                    if not P.Write is None:
                                        NewHeaders["content-type"] = self.__File_Type.content_type(
                                            result.split(".")[-1])

                            else:
                                warnings.warn(funcname + "的响应不是 str 不进行操作")
                        else:
                            if isinstance(result, bytes):
                                if P.Write is None:
                                    P.Write = result
                                else:

                                    warnings.warn(funcname + "原本响应已经存在数据 方法又返回数据 进行数据拼接")
                                    by = io.BytesIO()
                                    by.write(P.Write)
                                    by.write(result)
                                    P.Write = by.getvalue()
                                    by.close()
                            elif isinstance(result, str):
                                if P.Write is None:
                                    P.Write = result.encode(self.encoding)
                                else:
                                    warnings.warn(funcname + "原本响应已经存在数据 方法又返回数据 进行数据拼接")
                                    by = io.BytesIO()
                                    by.write(P.Write)
                                    by.write(result.encode(self.encoding))
                                    P.Write = by.getvalue()
                                    by.close()
                            else:
                                warnings.warn(funcname + "的响应不是 bytes 和 str 不进行操作")
                            if NewHeaders.get("content-type") is None:
                                if not P.Write is None:
                                    NewHeaders["content-type"] = self.__File_Type.content_type("txt")
                    # if NewHeaders.get("content-length") is None:
                    #     if not P.Write is None:
                    #         NewHeaders["content-length"] = len(P.Write)
                    # for n in NewHeaders:
                    #     P.Object.send_header(n, NewHeaders[n])


                    P.ToHeaders(NewHeaders)
                    if not P.Write is None:
                        P.Object.wfile.write(P.Write)





        except Exception as e:
            if self.__err is None:
                warnings.warn("你的总异常处理没写")
            else:
                self.__err["func"](e, *self.__err["args"], **self.__err["kwargs"])

    def route(self, route_: str, Type: str = "static"):
        """
        :param route_: 你的路由 正则
        :param Type: 你返回的是静态文件static ，还是动态数据active
        :return:
        """
        if ["static", "active"].count(Type) != 1:
            Type = "active"

        def Route(f):
            if f.__code__.co_argcount != 2:
                warnings.warn("route func:{} param length !=2".format(f.__name__))
            else:
                if not self.__routeMap.get(route_) is None:
                    warnings.warn("route 一样引起覆盖 : old: {} now: {}".format(self.__routeMap.get(route_), f.__code__))
                self.__routeMap[route_] = {"func": f, "Type": Type}
            return f

        return Route

    def err(self, *args, **kwargs):
        def error(f):
            try:
                if f.__code__.co_argcount < 1:
                    warnings.warn("err func param 0")
                elif f.__code__.co_argcount - (len(args) + len(kwargs)) != 1:
                    warnings.warn("要预留一个参数位置")
                else:
                    def trace(e, *args, **kwargs):
                        e = traceback.format_exc()
                        kwargs["func"](e, *kwargs["args"], **kwargs["kwargs"])

                    self.__err = {"func": trace, "args": (), "kwargs": {"func": f, "args": args, "kwargs": kwargs}}
            except Exception as e:
                raise Exception("你的异常方法出现错误", e)
            return f

        return error


"""
  socket 
 
"""


class read_stream:
    def __init__(self):
        """
        thisObject 你的Socket的 本身
        read 读取的数据大小按照 bufsize
        remoteObject TCP servlce情况下的客户对象
        remoteAddr 对方的Ip信息
        Atttibute 开启的基本参数
        bufsize 读取的字节大小
        """
        self.thisObject: socket.socket = None
        self.read: bytes = None
        self.remoteObject: socket.socket = None
        self.remoteAddr = None
        self.Atttibute = None
        self.bufsize: int = None

    def send(self, val):
        assert not self.thisObject is None, "socket 对象是 None"
        if isinstance(val, str) or isinstance(val, bytes):
            if isinstance(val, str):
                val = val.encode()
            if self.Atttibute["mode"] == "TCP":
                if self.Atttibute["Type"] == "servlce":
                    self.remoteObject.send(val)
                else:
                    self.thisObject.send(val)
            else:
                self.thisObject.sendto(val, self.remoteAddr)
        else:
            warnings.warn("数据不是str或者byte")


class Socket:
    def __init__(self, bufsize: int = 512):
        self.__TCPsocket: socket.socket = None
        self.__UDPsocket: socket.socket = None
        self.__err: dict = None

        self.bufsize = bufsize
        self.__TCPread = None
        self.__TCPsend = None

        self.__UDPread = None
        self.__UDPsend = None

        self.loop = asyncio.get_event_loop()

        _Thread_GO(self.Loop_TCP, err=self.__err).start()
        _Thread_GO(self.Loop_UDP, err=self.__err).start()

    def Loop_TCP(self):
        try:
            while True:
                self.__ReadTCP()

        except Exception as e:
            if self.__err is None:
                warnings.warn("你的总异常处理没写")
            else:
                self.__err["func"](e, *self.__err["args"], **self.__err["kwargs"])

    def Loop_UDP(self):
        er = 1
        while True:
            try:
                self.__ReadUDP()
                er = 1
            except OSError as e:
                print("这个异常是没分配到 端口给UDP，你可以转成UDP的servlce 分配固定端口，或者先进行send发生系统随机分配端口")
            except Exception as e:
                if self.__err is None:
                    warnings.warn("你的总异常处理没写")
                    print(e)
                else:
                    self.__err["func"](e, *self.__err["args"], **self.__err["kwargs"])
                if er > 10:
                    print("进入异常大于10s", er, " 退出 ")
                    return
                print("进入异常冷却 ", er, " s ")
                time.sleep(er)
                er *= 1.5

    def __ReadTCP(self):
        if not self.__TCPsocket is None and not self.__TCPread is None:
            rc = read_stream()
            rc.Atttibute = self.__TCPread["attribute"]
            rc.thisObject = self.__TCPsocket
            rc.bufsize = self.bufsize
            if self.__TCPread["attribute"]["Type"] == "servlce":
                rc.remoteObject, rc.remoteAddr = self.__TCPsocket.accept()
                rc.read = rc.remoteObject.recv(rc.bufsize)
                self.__TCPread["kwargs"][self.__TCPread["oneParam"]] = rc
                _Thread_GO(self.__TCPread["func"], err=self.__err, *self.__TCPread["args"],
                           **self.__TCPread["kwargs"]).start()


            else:
                rc.remoteObject = None
                rc.remoteAddr = (self.__TCPread["attribute"]["host"], self.__TCPread["attribute"]["port"])
                rc.read = self.__TCPsocket.recv(rc.bufsize)
                self.__TCPread["func"](rc, *self.__TCPread["args"],
                                       **self.__TCPread["kwargs"])

    def __ReadUDP(self):
        if not self.__UDPsocket is None and not self.__UDPread is None:
            rc = read_stream()
            rc.remoteObject = None
            rc.bufsize = self.bufsize
            rc.thisObject = self.__UDPsocket

            rc.read, rc.remoteAddr = rc.thisObject.recvfrom(rc.bufsize)

            rc.Atttibute = self.__UDPread["attribute"]
            self.__UDPread["func"](rc, *self.__UDPread["args"], **self.__UDPread["kwargs"])

    def __prepare(self, mode, Type, host, port):
        try:
            if mode == "TCP":
                if not self.__TCPsocket is None:
                    warnings.warn("TCP已经开始运行了")
                    return False
                else:
                    if Type == "servlce":
                        self.__TCPsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        self.__TCPsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        self.__TCPsocket.bind((host, port))
                        self.__TCPsocket.listen(10)
                    else:
                        self.__TCPsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        self.__TCPsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        self.__TCPsocket.connect((host, port))
                    return True
            else:
                if not self.__UDPsocket is None:
                    warnings.warn("UDP已经开始运行了")
                    return False
                if Type == "servlce":
                    self.__UDPsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    self.__UDPsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    self.__UDPsocket.bind((host, port))
                else:
                    self.__UDPsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    self.__UDPsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                return True
        except Exception as  e:
            if self.__err is None:
                warnings.warn("你的总异常处理没写")
            else:
                self.__err["func"](e, *self.__err["args"], **self.__err["kwargs"])
            return False

    def read(self, mode: str = "TCP", Type: str = "servlce", host: str = "127.0.0.1", port: int = 80, *args, **kwargs):
        """  open socket
        :param mode:  TCP or UDP
        :param Type:  client or servlce
        :param host:
        :param port:
        :param args:
        :param kwargs:
        :return:
        """
        try:
            mode = mode.upper()
            assert ["TCP", "UDP"].count(mode) == 1, "mode 错误"
            if (self.__prepare(mode, Type, host, port)):
                print("{} {} {} {} run".format(mode, Type, host, port))

                def func(f):

                    if f.__code__.co_argcount - (len(args) + len(kwargs)) != 1:
                        raise Exception("read 要预留第一个参数给读取")
                    else:
                        F = {"func": f, "attribute": {"mode": mode, "Type": Type, "host": host, "port": port},
                             "args": args, "kwargs": kwargs, "oneParam": f.__code__.co_varnames[0]}
                        if mode == "TCP":
                            self.__TCPread = F
                        else:
                            self.__UDPread = F

                    return f

                return func
            else:
                return None
        except Exception as e:
            if self.__err is None:
                warnings.warn("你的总异常处理没写")
            else:
                self.__err["func"](e, *self.__err["args"], **self.__err["kwargs"])
            return None

    def send(self, val, mode: str = "TCP", udp_remote=("127.0.0.1", 80)):
        """
        :param val:  传输内容
        :param mode: 现在传输的方式 可以不选
        :param udp_remote: UDP方式必填 你发给的对象地址
        :return:
        """
        try:
            assert not (self.__UDPsocket is None and self.__TCPsocket is None), "你没开启服务"
            assert isinstance(val, str) or isinstance(val, bytes), "你的数据类型不对"
            if isinstance(val, str):
                val = val.encode()
            mode = mode.upper()
            if not self.__UDPsocket is None and self.__TCPsocket is None:
                mode = "UDP"
            elif self.__UDPsocket is None and not self.__TCPsocket is None:
                mode = "TCP"

            if mode == "TCP":
                if self.__TCPread["attribute"]["Type"] == "servlce":
                    warnings.warn("你的TCP是servlce，不能使用这个主动send")
                else:
                    self.__TCPsocket.send(val)
            else:
                self.__UDPsocket.sendto(val, udp_remote)
        except Exception as e:
            if self.__err is None:
                warnings.warn("你的总异常处理没写")
            else:
                self.__err["func"](e, *self.__err["args"], **self.__err["kwargs"])

    def err(self, *args, **kwargs):
        def error(f):
            try:
                if f.__code__.co_argcount < 1:
                    warnings.warn("err func param 0")
                elif f.__code__.co_argcount - (len(args) + len(kwargs)) != 1:
                    warnings.warn("要预留一个参数位置")
                else:
                    def trace(e, *args, **kwargs):
                        e = traceback.format_exc()
                        kwargs["func"](e, *kwargs["args"], **kwargs["kwargs"])

                    self.__err = {"func": trace, "args": (), "kwargs": {"func": f, "args": args, "kwargs": kwargs}}
            except Exception as e:
                raise Exception("你的异常方法出现错误", e)
            return f

        return error

    def close(self):
        if not self.__UDPsocket is None:
            self.__UDPsocket.close()
            self.__UDPsocket = None
        if not self.__TCPsocket is None:
            self.__TCPsocket.close()
            self.__TCPsocket = None


"""
简单的支线程
"""


class _Thread_GO(threading.Thread):
    def __init__(self, func, err=None, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.err = err

    def run(self):
        try:
            self.func(*self.args, **self.kwargs)
        except Exception as e:
            if self.err is None:
                warnings.warn("你的总异常处理没写")
                print(e)
            else:
                self.err["func"](e, *self.err["args"], **self.err["kwargs"])


# go=GO_Thread()
# @go.go(x=1)
# def mode(x):
#   print(x)
#
# >>  x=1

class GO_Thread:
    def __init__(self):
        self.__active: dict = {}
        self.__predicted: list = []
        self.loop = asyncio.get_event_loop()
        self.__prepare()

    def __prepare(self):
        def run(se):
            se.loop.run_until_complete(se.__timer_clear())

        _Thread_GO(func=run, err=None, se=self).start()

    async def __timer_clear(self):
        errtime = 10
        while True:
            try:
                await asyncio.sleep(10)
                for k in self.__active:
                    if not self.isAlive(k):
                        self.remove(k)

                errtime = 10
            except Exception as e:
                print(e)
                time.sleep(errtime)
                errtime *= 1.5
                if errtime > 100:
                    warnings.warn("Go Thread clear  Error ", errtime, " exit")
                    break

    def isAlive(self, name):
        if not isinstance(name, str):
            name = name.__name__
        return self.__active[name].isAlive()

    def go(self, *args, **kwargs):

        def func(f):
            T = _Thread_GO(f, *args, **kwargs)
            self.__active[f.__name__] = T
            T.start()
            return f

        return func

    def getTask(self, f):
        task = self.__active.get(f.__name__)
        if not task is None:
            return task
        return None

    def remove(self, f):

        task = self.__active.get(f)
        if not task is None:
            del self.__active[f]
            print("func :", f, " del ok")
            return True
        return False


"""
 “数据库” 
"""


class SQL_Format:
    def __init__(self, dields, data, SQL):
        """
        :param dields: 字段
        :param data: 查询数据
        :param SQL:  你的数据库语句
        """
        self.data: list = data
        self.fields: dict = dields
        self.SQL: str = SQL


class Mytion_SQL:
    def __init__(self,
                 host,
                 user,
                 passwd,
                 port: int = 3306,
                 database: str = ""):
        import pymysql
        self.pymysql: pymysql = pymysql
        self.__user = user
        self.__passwd = passwd
        self.__port = port
        self.__err = None
        self.__database = database
        self.__MapFunc: dict = {}
        self.loop = asyncio.get_event_loop()
        self.__isConnect = True
        self.__MOTION = {"exec": self.__exec, "insert": self.__exec, "update": self.__exec, "query": self.__query,
                         "delete": self.__exec}
        try:
            self.__MYSQL = self.pymysql.Connect(host=host, user=user, password=passwd, port=port, database=database)
            self.__isConnect = True
        except Exception as e:
            print(e)
            self.__isConnect = False

    def begin(self,
              host
              , user,
              passwd,
              port: int = 3306,
              database: str = ""):
        try:
            self.__MYSQL = self.pymysql.Connect(host=host, user=user, password=passwd, port=port, database=database)
            self.__isConnect = True
        except Exception as e:
            print(e)
            self.__isConnect = False

    def close(self):
        self.__isConnect = False
        self.__MYSQL.close()

    def err(self, *args, **kwargs):
        """  注意异常处理方法必须带有 必须带有最少一个参数 第一个参数是 返回异常的 param数量必须少异常处理的数量
        :param args: 你给异常的参数
        :param kwargs:  你给异常的参数
        :return:
        """

        def defaultFunc(f):

            if f.__code__.co_argcount < 1:
                warnings.warn("ErrFunc param null")
            elif f.__code__.co_argcount - (len(args) + len(kwargs)) != 1:
                warnings.warn("ErrFunc param 没预留第一个参数")
            else:
                def trace(e, *args, **kwargs):
                    e = traceback.format_exc()
                    kwargs["func"](e, *kwargs["args"], **kwargs["kwargs"])
                    # {"func":f,"args":args,"kwargs":kwargs}

                self.__err = {"func": trace, "args": (), "kwargs": {"func": f, "args": args, "kwargs": kwargs}}
            return f

        return defaultFunc

    @staticmethod
    def query_DataToMap(fields, datas):

        assert isinstance(fields, dict) or len(fields) != 0, "fields none"
        assert isinstance(fields, dict) or len(datas) != 0, "data none"
        dataArray: list = []
        if len(fields) == len(datas[0]):
            for n in datas:
                now: dict = {}
                for k, v in enumerate(fields):
                    now[str(v[0])] = n[k]
                dataArray.append(now)
            return dataArray
        else:
            raise Exception("field != data value")

    def __query(self, exec: str):
        try:
            assert self.__isConnect, "not connet mysql"
            cursor = self.__MYSQL.cursor()
            cursor.execute(exec)
            fcursor = cursor.fetchall()
            cursor.close()
            return {"fields": cursor.description, "data": fcursor}
        except Exception as e:

            if self.__err is None:
                warnings.warn("ErrFunc param null")
            else:
                self.__err["func"](e, *self.__err["args"], **self.__err["kwargs"])

            return {"fields": None, "data": None}

    async def __exec(self, exec: str):
        try:
            assert self.__isConnect, "not connet mysql"
            cursor = self.__MYSQL.cursor()
            cursor.execute(exec)
            self.__MYSQL.commit()
            cursor.close()
        except Exception as e:
            if self.__err is None:
                warnings.warn("ErrFunc param null")
            else:
                self.__err["func"](e, *self.__err["args"], **self.__err["kwargs"])

    def cursor(self, exec: str):
        try:
            assert self.__isConnect, "not connet mysql"
            cursor = self.__MYSQL.cursor()
            cursor.execute(exec)
            self.__MYSQL.commit()
            return cursor
        except Exception as e:
            if self.__err is None:
                warnings.warn("ErrFunc param null")
            else:
                self.__err["func"](e, *self.__err["args"], **self.__err["kwargs"])
            return None

    def switch(self, types: str = "exec"):
        """
        :param types:  标记你属于什么操作 注意方法名称不要重复 引起覆盖
        :return:
        """
        try:
            if types is None:
                raise Exception("None")
            assert ["exec", "insert", "update", "delete", "query"].count(types) == 1, "not select"
            if ["exec", "insert", "update", "delete", "query"].count(types) == 1:
                def defaultFunc(f):
                    self.__MapFunc[f.__name__] = {"origin": types, "func": f}
                    return f
            else:
                def defaultFunc(f):
                    return f
            return defaultFunc
        except Exception as e:
            if self.__err is None:
                warnings.warn("ErrFunc param null")
            else:
                self.__err["func"](e, *self.__err["args"], **self.__err["kwargs"])
            return None

    def run(self, objectname, *args, **kwargs):
        """
        :param objectname:   你调用的方法 可以是function 也可以是字符串
        :param args:  query情况下 传递的参数 要是有sql query语句会执行 然后结果返回给之前的那个参数覆盖
        :param kwargs:  query情况下 传递的参数 要是有sql query语句会执行 然后结果返回给之前的那个参数覆盖
        :return: query情况下 你的方法要是有返回值 那就调用后返回，其他情况返回None

        """
        try:
            assert not objectname is None, "objectname none"
            func = None
            if isinstance(objectname, str):
                func = objectname
            else:
                func = objectname.__name__

            assert not func is None, "objectname no func or str"
            func = self.__MapFunc.get(func)
            assert not func is None, "function no insert map "
            if func["origin"] == "query":
                if func["func"].__code__.co_argcount < 1:
                    raise Exception("parame length min 1")
                else:
                    nowlist = []
                    for i, v in enumerate(args):

                        if isinstance(v, str):
                            if re.findall("^\s*?select.+$", v).__len__() > 0:
                                result = self.__query(v)
                                nowlist.append(
                                    SQL_Format(result["fields"], self.query_DataToMap(result["fields"], result["data"]),
                                               v))
                            else:
                                nowlist.append(v)
                        else:
                            nowlist.append(v)

                    for k in kwargs:
                        if isinstance(kwargs[k], str):
                            if re.findall("^\s*?select.+$", kwargs[k]).__len__() > 0:
                                result = self.__query(kwargs[k])
                                kwargs[k] = SQL_Format(result["fields"],
                                                       self.query_DataToMap(result["fields"], result["data"]),
                                                       kwargs[k])

                    return func["func"](*nowlist, **kwargs)

            else:
                SQL = func["func"](*args, **kwargs)
                self.loop.run_until_complete(self.__exec(SQL))
                return None
        except Exception as e:
            if self.__err is None:
                warnings.warn("ErrFunc param null")
            else:
                self.__err["func"](e, *self.__err["args"], **self.__err["kwargs"])
            return None
