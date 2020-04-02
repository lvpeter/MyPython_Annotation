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

    #这是 a等价于 SQL语句A的查询结果
    
    #这是 b等价于 SQL语句B的查询结果
    
    #这是 c等价于 SQL语句C的查询结果
    
    #d 还是等于1
    
    #e 还是字符 "2"
    
    pass
     
增加

@sql.switch("insert")
def add(x,y):
   retrun "insert into table(column1,column2) value ({},{})".format(x,y)
   这里的返回字符串 会被执行

调用

sql.run(add,"参数"，"参数")

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
   






