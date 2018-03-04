#!/usr/bin/env python
# -*- coding: utf-8 -*-

import frida
import sys
import optparse
import re
import time

global session

def enume_proc():
    global session
    rdev = frida.get_remote_device()
    session = rdev.attach("com.tencent.mm")  
    modules = session.enumerate_modules()
    for module in modules:
        print module
        export_funcs = module.enumerate_exports()
        print "\tfunc_name\tRVA"
        for export_func in export_funcs:
            print "\t%s\t%s"%(export_func.name,hex(export_func.relative_address))

#枚举某个进程加载的所有模块
def proc_module_show():
    global session
    rdev = frida.get_remote_device()
    session = rdev.attach("com.tencent.mm")  #如果存在两个一样的进程名可以采用rdev.attach(pid)的方式
    modules = session.enumerate_modules()
    for module in modules:
        print module
        export_funcs = module.enumerate_exports()
        print "\tfunc_name\tRVA"
        for export_func in export_funcs:
            print "\t%s\t%s"%(export_func.name,hex(export_func.relative_address))


#hook native函数
def native_hook(name):
    global session
    rdev = frida.get_remote_device()
    session = rdev.attach(name)
    scr = """
    var gdata,glen,gname;
    Interceptor.attach(Module.findExportByName("libmono.so" , "mono_image_open_from_data_with_name"), {
        
        onEnter: function(args) {
            var showstr;
            var cont;
            
            showstr=Memory.readCString(args[5]);
            
            send(showstr);
            send(args[0]+args[1]+args[2]+args[3]+args[4]+args[5]);

            gdata=args[0];
            glen=args[1];
            gname=showstr;
            if(showstr=='/data/app/com.tencent.tmgp.sgame-1/base.apk/assets/bin/Data/Managed/Assembly-CSharp.dll')
            {
                var temp;
                send("Assembly-CSharp.dll");
                gdata=args[0];
                glen=args[1];
                send("data:"+gdata); 
                send("len:"+glen);     
                send("needcopy"+args[2]);   
            }
        },
        onLeave:function(retval){

        }
    });
    Interceptor.attach(Module.findExportByName("libc.so" , "time"), {
        onEnter: function(args) {
    
        },
        onLeave:function(retval){
            //send("timehook");
            args[0]=10;
            return 10;
        }
    });
     Interceptor.attach(Module.findExportByName("libc.so" , "clock"), {
        onEnter: function(args) {
    
        },
        onLeave:function(retval){
            //send("timehook");
            return 10;
        }
    });
    Interceptor.attach(Module.findExportByName("libc.so" , "open"), {
        onEnter: function(args) {
             
        },
        onLeave:function(retval){
            if(name=="/proc/self/status"||name=="/proc/stat")
            {
                send("statuhook");
                return 0;
            }
            return retval;
        }
    });
    Interceptor.attach(Module.findExportByName("libc.so" , "getuid"), {
        onEnter: function(args) {
           //send("hellouid");
        },
        onLeave:function(retval){
            return 0x306;
        }
    });
    Interceptor.attach(Module.findExportByName("libc.so" , "memcpy"), {
        onEnter: function(args) {
            if(args[1]==gdata)
                {
                    send("mudidizhi:"+args[0]);
                    send("mudilen:"+args[2]);
                }
               
        },
        onLeave:function(retval){
            
        }
    });
    """
    script = session.create_script(scr)
    script.on("message" , on_message2)
    script.load()
    sys.stdin.read()
#hook native函数
def native_hook2(name):
    global session
    rdev = frida.get_remote_device()
    session = rdev.attach(name)
    scr = """
    var name;
    Interceptor.attach(Module.findExportByName("libc.so" , "memcpy"), {
        onEnter: function(args) {
            send("args[1]");
               
        },
        onLeave:function(retval){
            
        }
    });
    """
    script = session.create_script(scr)
    script.on("message" , on_message2)
    script.load()
    sys.stdin.read()

#hook native函数
def native_hook3(name):
    global session
    rdev = frida.get_remote_device()
    session = rdev.attach(name)
    scr = """
    Interceptor.attach(Module.findExportByName("libc.so" , "memcmp"), {
        onEnter: function(args) {
            //0xf001f0e7
           /*if(args[1]==0xeff001f0){
                    send("arm_breakpoint_test");
                }*/
           if(args[1]==0x10de||args[1]==0xde10){
                    send("breakpoint_test");
                }
        },
        onLeave:function(retval){
            
        }
    });
    """
    script = session.create_script(scr)
    script.on("message" , on_message2)
    script.load()
    sys.stdin.read()

def on_message(message, data):
    print message
#从JS接受信息
def on_message2(message, data):
	if message.has_key('payload'):
		payload = message['payload']
		if isinstance(payload, dict):
			deal_message(payload)
		else:
			print message

#处理JS中不同的信息
def deal_message(payload):
	global UIMESSAGE
	global APPINFO
	global appname
	global appdoc
	global appurl
	appdoc=''
	appurl=''
	k=0
	#基本信息输出
	if payload.has_key('con'):
		print "%x"%payload['con']
'''如下代码为hook微信（测试版本为6.3.13,不同版本由于混淆名字的随机生成的原因或者代码改动导致名称不一样）com.tencent.mm.sdk.platformtools.ay类的随机数生成函数，让微信猜拳随机（tye=2）,二摇色子总是为6点（type=5）'''



'''枚举手机进程'''
def enume_proc():
    rdev = frida.get_remote_device()
    processes = rdev.enumerate_processes()
    for process in processes:
        print process
def find_proc(name):
    rdev = frida.get_remote_device()
    processes = rdev.enumerate_processes()
    for process in processes:
        if process.name==name:
            return True
    return False
def main():
    if len(sys.argv)>2:
        name=sys.argv[2]
    else:
        name="com.tencent.tmgp.sgame"

    if sys.argv[1]=='ps':
        enume_proc()

    elif sys.argv[1]=='nhook':
        #等待程序启动，直接附加
        print "please app waiting launched..."
        while True:
            if find_proc(name)==False:
                continue
            else:
                time.sleep(2)
            	print "find process"
            	native_hook(name)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        if session:
            session.detach()
        sys.exit()
    else:
        pass
    finally:
        pass
