# MyPython_Annotation
记录自己的进步
适合自己的python 注解 
# MYSQL
首先要安装有pymysql 这个库

调用

      import Annotation

      sql=Annotation.Mytion_SQL(host="0.0.0.0",user="use",passwd="passwd",port=3306,database= "")

      sql.switch 这个是记录你操作的方法 必填参数为 ["exec","insert","update","delete","query"] 默认是exec

      sql.run(“第一个参数是你的方法或者你方法名称”,"你的语句或者参数"..)

查询

      @sql.switch("query")
      del q(x):
        #这里的x 是返回的查询数据class 
        #    class 包含
        #    :param dields: 字段
        #    :param data: 查询数据
        #    :param SQL:  你的数据库语句
          return x
          
调用

sql.run(q,"SQL语句") or sql.run(q,x="SQL语句")

可以多个语句

栗子：

sql.run(q,a="SQL语句A",b="SQL语句B",c="SQL语句C",d=1,e="2")

    @sql.switch("query")
    def q(a,b,c,d,e):    
    # 这是 a等价于 SQL语句A的查询结果 
    # 这是 b等价于 SQL语句B的查询结果   
    # 这是 c等价于 SQL语句C的查询结果 
    #d 还是等于1  
    #e 还是字符 "2"
    pass

*******************************************************************************************
增加

    @sql.switch("insert")
    def add(x,y):
       retrun "insert into table(column1,column2) value ({},{})".format(x,y)
       这里的返回字符串 会被执行

调用
sql.run(add,"参数"，"参数")
*******************************************************************************************
异常
全部的异常会引起这个方法 算是总处理吧

      @sql.err("可选参数")
      der errfunc(e,"可选参数")：
         ....
          e 要预留第一个参数给异常返回
   
   
# Thread 
#简单的支线程

      go=GO_Thread()

栗子：

      @go.go()
      def thread1():
         print(“我进入支线程了”)
         
或者
      
      @go.go(a="可选参数"...)
      def thread2(a):
         print(a)
         #a=可选参数
   
   
..................   
# 2020-04-06 18：13 
继续增加了 webservlce 和 Socket
属于自己的 才是最方便的

web servlce

web 是基于python自带的http基础包建立

    from http import server, HTTPStatus, cookies
    from urllib import parse

开启 

    web=Annotation.WebServlce("127.0.0.1",80)

这样 就可以启动端口服务 不然也可以，

     web=Annotation.WebServlce()
     web.start(host,port)
     
都可以启动服务

异常
与之前一样
   
      @web.err()
      def err(x):
             x是异常的返回内容
             print(x)
             
异常部分不是很完善，以后再搞


路由


       """
        :param route_: 你的路由 正则
        :param Type: 你返回的是静态文件static ，还是动态数据active 
        :return:
        """
       @web.route("/",Type="active")
       def ser1(r,w):
           强制性要求 路由方法要有2个参数，r 对应request，w对应response ，因为我golang习惯这样
           pass
           
           
           
          @web.route("/",Type="static")
          def ser1(r,w):
           强制性要求 路由方法要有2个参数，r 对应request，w对应response ，因为我golang习惯这样
            return “内容”  
            
            
当你的属性是static 那么你的返回内容是必须静态路径，因为返回给前端的是你这个路径的文件，
其中文件，其中注意要填写content-type 虽然我有写几个常用的content-type 的适应
        
          @web.route("/",Type="static")
          def ser1(r,w):
           强制性要求 路由方法要有2个参数，r 对应request，w对应response ，因为我golang习惯这样
            w.headers["content-type"]="text/html"
            w.status=200
            return “内容” 
            
        
当你的属性是active 那么你的返回内容是就是你要返回的内容，当然也可以不写返回 不是使用return 那么你必须
要调用 w.Write 来写你要返回的内容

          @web.route("/",Type="active")
          def ser1(r,w):
           强制性要求 路由方法要有2个参数，r 对应request，w对应response ，因为我golang习惯这样
            w.headers["content-type"]="text/html"
            w.status=200
            return “内容”   
              @web.route("/",Type="active")
              
          def ser2(r,w):
           强制性要求 路由方法要有2个参数，r 对应request，w对应response ，因为我golang习惯这样
            w.headers["content-type"]="text/html"
            w.status=200
            w.Write="内容内容".encode()
 没做GET的路由区分POST,想知道是POST，还是GET 就 r.Method， 我觉得不区分感觉更好写点
 
 读取前端传来的数据 r.body ,记得解码这是bytes的
 
 Cookie 操作
 
          @web.route("/",Type="active")
          def ser1(r,w):
           强制性要求 路由方法要有2个参数，r 对应request，w对应response ，因为我golang习惯这样
             r.cookies 是读取前端传来的 是字典格式
             
             返回cookie
              w.addCookie("k1","123")
              w.setCookie("k2", "111")
           
           具体的参数
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
              
#  Socket 的TCP 和UDP
可以支持同时开启TCP和UDP服务 但是只能各一个 ，因为我就写了2个支线程运行

使用
    sc=Annotation.Socket(bufsize=512) 这里的参数是每次读写的大小
    
 开启和监听
    
      我把开启和读取监听做成一个方法了省事,默认都开启了端口的重用
       """  open socket
        :param mode:  TCP or UDP
        :param Type:  client or servlce
        :param host:
        :param port:
        :param args:
        :param kwargs:
        :return:
        """
      @sc.ead(mode="TCP",Type="servlce"，....):
      def servlce(x,...):
          参数的第一个强制性给类read_stream 
        """ read_stream的参数
        thisObject 你的Socket的 本身
        read 读取的数据,大小按照 bufsize
        remoteObject TCP servlce情况下的客户对象
        remoteAddr 对方的Ip信息
        Atttibute 开启的基本参数
        bufsize 读取的字节大小
         以及被动发送的send(val)发送
        """
           print(x.read())
           x.send("收到".encoed())
       
       
            
       
         
          
          
       
主动发送,TCP 用于client，UDP要先知道addr 

        """
        :param val:  传输内容
        :param mode: 现在传输的方式 可以不选
        :param udp_remote: UDP方式必填 你发给的对象地址
        :return:
        """ 
       sc.send()
       
    
异常，老样子
     
     @sc.err
     def err(x):
        ......
关闭

     sc.close()
     
     
     
。。。。。。。。。。。。。。。。

还在努力学习，接下来想开启微信公众号的注解，争取快速简单无脑实现微信公众号的功能     


