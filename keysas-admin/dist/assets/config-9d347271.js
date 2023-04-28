import{_ as y,o as n,c as i,w as d,v as c,a as s,t as _,b as a,d as g,e as p,F as k,f as v,N as I,g as h,h as b}from"./index-cbd18d6f.js";import{b as w}from"./index-e311e5e3.js";import{d as D,e as F,f as H,h as R,j as U}from"./utils-03851a22.js";const E={name:"SSHKeys",computed:{},data(){return{publicKey:"",privateKey:"",keysError:"",show:!1}},methods:{async PublicKeyPath(){this.publicKey=await D()},async PrivateKeyPath(){this.privateKey=await F()},async onSubmit(){console.log("Form submitted"),await w("save_sshkeys",{public:this.publicKey,private:this.privateKey})?(this.ShowTwoSec(),console.log("SSH keys saved")):console.log("Failed to save ssh keys")},ShowTwoSec(){this.show=!0,setTimeout(()=>{this.show=!1},2e3)}}},q=s("label",{type:"text"}," Path to your SSH public key:",-1),B={class:"text-center"},V={key:0,class:"error"},N=s("br",null,null,-1),A=s("br",null,null,-1),L=s("label",{type:"text"}," Path to your SSH private key:  ",-1),T={class:"text-center"},O={key:1,class:"error"},z=s("br",null,null,-1),M=s("br",null,null,-1),G={class:"submit"},W=s("button",{class:"send btn btn-outline-success btn-lg shadow"},[s("i",{class:"bi bi-check-square"}," Ok")],-1),j=s("br",null,null,-1),J=s("br",null,null,-1),Y={key:0,class:"validate animate__animated animate__zoomIn text-success"};function Q(r,t,u,m,e,l){return n(),i("form",{class:"box",onSubmit:t[4]||(t[4]=g((...o)=>l.onSubmit&&l.onSubmit(...o),["prevent"]))},[q,d(s("input",{type:"text",required:"","onUpdate:modelValue":t[0]||(t[0]=o=>e.publicKey=o),id:"publicKey"},null,512),[[c,e.publicKey]]),s("div",B,[s("button",{class:"btn btn-outline-secondary btn-sm shadow",onClick:t[1]||(t[1]=(...o)=>l.PublicKeyPath&&l.PublicKeyPath(...o))},"Browse")]),e.keysError?(n(),i("div",V,_(e.keysError),1)):a("",!0),N,A,L,d(s("input",{type:"text",required:"","onUpdate:modelValue":t[2]||(t[2]=o=>e.privateKey=o),id:"private"},null,512),[[c,e.privateKey]]),s("div",T,[s("button",{class:"btn btn-outline-secondary btn-sm shadow",onClick:t[3]||(t[3]=(...o)=>l.PrivateKeyPath&&l.PrivateKeyPath(...o))},"Browse")]),e.keysError?(n(),i("div",O,_(e.keysError),1)):a("",!0),z,M,s("div",G,[W,j,J,e.show?(n(),i("h3",Y,"Done !")):a("",!0)])],32)}const X=y(E,[["render",Q]]);const Z={name:"DisplaySSHConfig",computed:{},data(){return{pubKey:"",privKey:"",hide:!0}},mounted(){this.getSSHKeys()},methods:{getSSHKeys(){w("get_sshkeys").then(r=>{this.pubKey=r[0],this.privKey=r[1],console.log("Path: "+this.pubKey),console.log("Path: "+this.privKey)}).catch(r=>console.error(r))}}},ss=v('<div class="tip"><h5 class="text-info"><i class="bi bi-moon-stars-fill"> Help</i></h5><br><span class="tip-text">You must provide the application a dedicated SSH keypair to connect your Keysas stations.</span><span class="tip-text">Only ED25519 in PEM format is supported.<br> To generate this new SSH keypair on your local machine, open a terminal and enter to following command:</span><br><span class="tip-text"><b>ssh-keygen -m PEM -t ed25519 -f mykey</b></span></div><br>',2),ts={key:0,class:"custom-li tip"},es={class:"text-center"},os=s("span",{class:"bi bi-caret-up-fill"}," Hide registred SSH keys",-1),ns=[os],is=s("br",null,null,-1),ls=s("br",null,null,-1),rs={class:"List"},as={class:"list-group-item"},ds={class:"list-group-item list-group-item-light"},cs=s("br",null,null,-1),us={class:"text-secondary"},_s={class:"list-group-item list-group-item-light"},hs=s("br",null,null,-1),bs={class:"text-secondary"},ys={key:1},ms=s("span",{class:"bi bi-caret-down-fill"}," Show registred SSH keys",-1),ps=[ms];function gs(r,t,u,m,e,l){return n(),i(k,null,[ss,e.hide?(n(),i("div",ys,[s("button",{class:"send btn btn-light shadow",onClick:t[1]||(t[1]=o=>{e.hide=!1,l.getSSHKeys()})},ps)])):(n(),i("div",ts,[s("div",es,[s("button",{class:"send btn btn-light shadow",onClick:t[0]||(t[0]=o=>{e.hide=!0,l.getSSHKeys()})},ns),is,ls,s("div",rs,[s("ul",as,[s("li",ds,[p("Registred public key:"),cs,s("span",us,_(e.pubKey),1)]),s("li",_s,[p("Registred private key:"),hs,s("span",bs,_(e.privKey),1)])])])])]))],64)}const vs=y(Z,[["render",gs]]);const ws={name:"SigningKeys",computed:{},data(){return{rootKeyPath:"",pkiDir:"",orgName:"",orgUnit:"",country:"",validity:"",adminPwd:"",pkiFolder:"",keysError:"",show:!1,waiting:!1,showLoadPKIForm:!1,showRootKeyForm:!1,showPkiDirForm:!1}},methods:{async RootKeyPath(){this.rootKey=await H()},async PKIFolder(){this.pkiFolder=await R()},async PKIDir(){this.pkiDir=await U()},async submitPKIFolderForm(){console.log("PKI Folder form submission")},async submitRootCAForm(){console.log("Root CA form submission")},async submit(){this.waiting=!0,await this.submitPKIDirForm()},async submitPKIDirForm(){console.log("PKI Dir form submission"),await w("generate_pki_in_dir",{orgName:this.orgName,orgUnit:this.orgUnit,country:this.country,validity:this.validity,adminPwd:this.adminPwd,pkiDir:this.pkiDir}).then(r=>this.pkiGenerated()).catch(r=>console.error(r))},async pkiGenerated(){this.waiting=!1,this.ShowFiveSec()},ShowFiveSec(){this.show=!0,setTimeout(()=>{this.show=!1},5e3)}}},Ss={class:"row align-items-start box"},ks={class:"col"},fs={class:"col"},Ks={key:0},Ps=s("label",{type:"text"}," Path to your PKI folder:",-1),xs={class:"text-center"},$s={key:0,class:"error"},Cs=s("br",null,null,-1),Is=s("br",null,null,-1),Ds={class:"submit"},Fs=s("i",{class:"bi bi-check-square"}," Ok",-1),Hs=[Fs],Rs=s("br",null,null,-1),Us=s("br",null,null,-1),Es={key:0,class:"validate animate__animated animate__zoomIn text-success"},qs={key:1},Bs=s("label",{type:"text"}," Path to your Root CA key file (PKCS#12):",-1),Vs={class:"text-center"},Ns={key:0,class:"error"},As=s("br",null,null,-1),Ls=s("br",null,null,-1),Ts={class:"submit"},Os=s("i",{class:"bi bi-check-square"}," Ok",-1),zs=[Os],Ms=s("br",null,null,-1),Gs=s("br",null,null,-1),Ws={key:0,class:"validate animate__animated animate__zoomIn text-success"},js={key:2},Js=s("label",{type:"text"}," Organization name:",-1),Ys=s("label",{type:"text"}," PKI name:",-1),Qs=s("label",{type:"text"}," Country (first two letters):",-1),Xs=s("label",{type:"text"}," Validity (days):",-1),Zs=s("label",{type:"text"}," Select directory:",-1),st={class:"text-center"},tt=s("label",{type:"text"}," Password:",-1),et={key:0,class:"error"},ot=s("br",null,null,-1),nt=s("br",null,null,-1),it={class:"submit"},lt=s("i",{class:"bi bi-check-square"}," Ok",-1),rt=[lt],at={key:1},dt=s("span",{class:"spinner-border text-info"},null,-1),ct=s("br",null,null,-1),ut={key:2,class:"validate animate__animated animate__zoomIn text-success"};function _t(r,t,u,m,e,l){return n(),i("div",Ss,[s("div",ks,[s("button",{class:"send btn btn-info btn-lg shadow",onClick:t[0]||(t[0]=o=>{e.showLoadPKIForm=!e.showLoadPKIForm,e.showRootKeyForm=!1,e.showPkiDirForm=!1})}," Load from local PKI ")]),s("div",fs,[s("button",{class:"send btn btn-info btn-lg shadow",onClick:t[1]||(t[1]=o=>{e.showLoadPKIForm=!1,e.showRootKeyForm=!1,e.showPkiDirForm=!e.showPkiDirForm})}," Create a new PKI ")]),e.showLoadPKIForm?(n(),i("div",Ks,[s("form",{class:"add-form",onSubmit:t[5]||(t[5]=g((...o)=>r.onSubmit&&r.onSubmit(...o),["prevent"]))},[Ps,d(s("input",{type:"text",required:"","onUpdate:modelValue":t[2]||(t[2]=o=>e.pkiFolder=o),id:"pkiFolder"},null,512),[[c,e.pkiFolder]]),s("div",xs,[s("button",{class:"btn btn-outline-secondary btn-sm shadow",onClick:t[3]||(t[3]=(...o)=>l.PKIFolder&&l.PKIFolder(...o))},"Browse")]),e.keysError?(n(),i("div",$s,_(e.keysError),1)):a("",!0),Cs,Is,s("div",Ds,[s("button",{class:"send btn btn-outline-success btn-lg shadow",onClick:t[4]||(t[4]=(...o)=>l.submitPKIFolderForm&&l.submitPKIFolderForm(...o))},Hs),Rs,Us,e.show?(n(),i("h3",Es,"Done !")):a("",!0)])],32)])):a("",!0),e.showRootKeyForm?(n(),i("div",qs,[s("form",{class:"add-form",onSubmit:t[9]||(t[9]=g((...o)=>r.onSubmit&&r.onSubmit(...o),["prevent"]))},[Bs,d(s("input",{type:"text",required:"","onUpdate:modelValue":t[6]||(t[6]=o=>e.rootKeyPath=o),id:"rootKey"},null,512),[[c,e.rootKeyPath]]),s("div",Vs,[s("button",{class:"btn btn-outline-secondary btn-sm shadow",onClick:t[7]||(t[7]=(...o)=>l.RootKeyPath&&l.RootKeyPath(...o))},"Browse")]),e.keysError?(n(),i("div",Ns,_(e.keysError),1)):a("",!0),As,Ls,s("div",Ts,[s("button",{class:"send btn btn-outline-success btn-lg shadow",onClick:t[8]||(t[8]=(...o)=>l.submitRootCAForm&&l.submitRootCAForm(...o))},zs),Ms,Gs,e.show?(n(),i("h3",Ws,"Done !")):a("",!0)])],32)])):a("",!0),e.showPkiDirForm?(n(),i("div",js,[s("form",{class:"add-form",onSubmit:t[18]||(t[18]=g((...o)=>r.onSubmit&&r.onSubmit(...o),["prevent"]))},[Js,d(s("input",{type:"text",required:"","onUpdate:modelValue":t[10]||(t[10]=o=>e.orgName=o),id:"orgName"},null,512),[[c,e.orgName]]),Ys,d(s("input",{type:"text",required:"","onUpdate:modelValue":t[11]||(t[11]=o=>e.orgUnit=o),id:"orgUnit"},null,512),[[c,e.orgUnit]]),Qs,d(s("input",{type:"text",required:"","onUpdate:modelValue":t[12]||(t[12]=o=>e.country=o),id:"country"},null,512),[[c,e.country]]),Xs,d(s("input",{type:"text",required:"","onUpdate:modelValue":t[13]||(t[13]=o=>e.validity=o),id:"validity"},null,512),[[c,e.validity]]),Zs,d(s("input",{type:"text",required:"","onUpdate:modelValue":t[14]||(t[14]=o=>e.pkiDir=o),id:"pkiDir"},null,512),[[c,e.pkiDir]]),s("div",st,[s("button",{class:"btn btn-outline-secondary btn-sm shadow",onClick:t[15]||(t[15]=(...o)=>l.PKIDir&&l.PKIDir(...o))},"Browse")]),tt,d(s("input",{type:"password",required:"","onUpdate:modelValue":t[16]||(t[16]=o=>e.adminPwd=o),id:"adminPwd"},null,512),[[c,e.adminPwd]]),e.keysError?(n(),i("div",et,_(e.keysError),1)):a("",!0),ot,nt,s("div",it,[e.waiting?a("",!0):(n(),i("button",{key:0,class:"send btn btn-outline-success btn-lg shadow",onClick:t[17]||(t[17]=o=>{l.submit()})},rt)),e.waiting?(n(),i("div",at,[p(" Wait while creating PKI... "),dt])):a("",!0),ct,e.show?(n(),i("h3",ut,"PKI successfully created !")):a("",!0)])],32)])):a("",!0)])}const ht=y(ws,[["render",_t]]);const bt={name:"DisplaySigningConfig",computed:{},data(){return{rootKey:"",hide:!0}},mounted(){},methods:{getRootKey(){let r=localStorage.getItem("rootCA");this.rootKey=JSON.parse(r).pub,console.log("Path: "+this.rootKey)}}},yt=v('<div class="tip"><h5 class="text-info"><i class="bi bi-moon-stars-fill"> Help</i></h5><br><span class="tip-text">If you are configuring <b>Keysas-admin</b> for the first time, click on <b>Create a new PKI</b>.</span><span class="tip-text"> Then, provide all the requested information to allow us to create a new PKI for you.<br> When done, you will be able to start signing new outgoing USB devices.<br></span><span class="tip-text">If you have already created a PKI and you want to restore it, choose <b>Load from local PKI</b></span></div><br>',2),mt={key:0,class:"custom-li tip"},pt={class:"text-center"},gt=s("span",{class:"bi bi-caret-up-fill"}," Hide registred Root CA key",-1),vt=[gt],wt=s("br",null,null,-1),St=s("br",null,null,-1),kt={class:"List"},ft={class:"list-group-item"},Kt={class:"list-group-item list-group-item-light"},Pt=s("br",null,null,-1),xt={class:"text-secondary"},$t={key:1},Ct=s("span",{class:"bi bi-caret-down-fill"}," Show registred Root CA key",-1),It=[Ct];function Dt(r,t,u,m,e,l){return n(),i(k,null,[yt,e.hide?(n(),i("div",$t,[s("button",{class:"send btn btn-light shadow",onClick:t[1]||(t[1]=o=>{e.hide=!1,l.getRootKey()})},It)])):(n(),i("div",mt,[s("div",pt,[s("button",{class:"send btn btn-light shadow",onClick:t[0]||(t[0]=o=>{e.hide=!0,l.getRootKey()})},vt),wt,St,s("div",kt,[s("ul",ft,[s("li",Kt,[p("Registred Root CA key:"),Pt,s("span",xt,_(r.pubKey),1)])])])])]))],64)}const Ft=y(bt,[["render",Dt]]),Ht={name:"SignKey",props:{signUsbStatus:Boolean},computed:{},data(){return{password:"",keys:"",hide:!1,showSign:!1,passwordError:!1}},methods:{async SignDevice(){console.log("Calling sign_key"),await w("sign_key",{password:this.password}).then(r=>console.log("good")).catch(r=>console.error(r))},async onSubmitSign(){this.showSign=!0}}},Rt={class:"box"},Ut={class:"row"},Et={class:"col-sm"},qt=s("label",{type:"text"},"Password:",-1),Bt={key:0,class:"error"},Vt=s("br",null,null,-1),Nt={class:"submit"},At=s("i",{class:"bi bi-check-square"}," Sign !",-1),Lt=[At],Tt=s("br",null,null,-1),Ot=s("br",null,null,-1),zt={key:0,class:"validate animate__animated animate__zoomIn text-success"},Mt=v('<div class="col-sm"><div class="tip"><span class="text-info"><i class="bi bi-moon-stars-fill"> Help</i></span><br><br><span class="tip-text">Enter your signing password and plug the new device within 30 seconds to sign it.</span></div></div>',1),Gt={key:0,class:"term"},Wt=s("br",null,null,-1),jt={key:0,class:"animate__animated animate__flash textterm text-success"},Jt={key:1,class:"animate__animated animate__flash textterm text-danger"},Yt={key:2,class:"textterm spinner-border text-info"};function Qt(r,t,u,m,e,l){return n(),i("div",Rt,[s("div",Ut,[s("div",Et,[s("form",{class:"add-form",onSubmit:t[2]||(t[2]=g((...o)=>l.onSubmitSign&&l.onSubmitSign(...o),["prevent"]))},[qt,d(s("input",{type:"password",required:"","onUpdate:modelValue":t[0]||(t[0]=o=>e.password=o),placeholder:"8 caracters min",id:"password"},null,512),[[c,e.password]]),e.passwordError?(n(),i("div",Bt,_(e.passwordError),1)):a("",!0),Vt,s("div",Nt,[s("button",{onClick:t[1]||(t[1]=o=>l.SignDevice()),class:"send btn btn-outline-success shadow"},Lt),Tt,Ot,r.show?(n(),i("h3",zt,"Done !")):a("",!0)])],32)]),Mt]),e.showSign?(n(),i("div",Gt,[p(" Please plug a new USB device... "),Wt,u.signUsbStatus?(n(),i("span",jt,"If the provided password is good, the new device should signed now !")):r.shutdownStatus===!1?(n(),i("span",Jt,"Error: can't connect to the Keysas station or somthing went wrong !")):(n(),i("span",Yt))])):a("",!0)])}const Xt=y(Ht,[["render",Qt]]),Zt={name:"RevokeDevice",props:{revokeUsbStatus:Boolean},computed:{},data(){return{keys:"",hide:!1}},async mounted(){this.keys=await getKeys()},methods:{async displayKeysasList(){loadStore(),this.keys=await getKeys()}}},se={class:"box"},te={class:"container"},ee={class:"row"},oe=v('<div class="col-sm"><div class="tip"><span class="text-info"><i class="bi bi-moon-stars-fill"> Help</i></span><br><br><span class="tip-text">Click on the button and plug the USB key in your Keysas station within 30 seconds to revoke it</span><br></div></div>',1),ne={class:"col-sm"},ie={class:"tip"},le=s("i",{class:"bi bi-check-square"}," Revoke !",-1),re=[le],ae={class:"term"},de=s("br",null,null,-1),ce={key:0,class:"animate__animated animate__flash textterm text-success"},ue={key:1,class:"animate__animated animate__flash textterm text-danger"},_e={key:2,class:"textterm spinner-border text-info"};function he(r,t,u,m,e,l){return n(),i("div",se,[s("div",te,[s("div",ee,[oe,s("div",ne,[s("div",ie,[s("button",{class:"send btn btn-lg btn-outline-danger shadow",onClick:t[0]||(t[0]=o=>r.onSubmitRevoke())},re)])])])]),s("div",ae,[p(" Revoking the output key:"),de,u.revokeUsbStatus?(n(),i("span",ce,"Success")):u.revokeUsbStatus===!1?(n(),i("span",ue,"Error: can't connect to the Keysas station !")):(n(),i("span",_e))])])}const be=y(Zt,[["render",he]]),ye={name:"AddView",components:{NavBar:I,SignKey:Xt,SSHKeys:X,DisplaySSHConfig:vs,SigningKeys:ht,DisplaySigningConfig:Ft,RevokeDevice:be},computed:{},data(){return{ShowSign:!1,ShowRevoke:!1,ShowSSH:!1,ShowPKI:!1}},methods:{flush(){this.ShowSign=!1,this.ShowRevoke=!1,this.ShowSSH=!1,this.ShowPKI=!1}}},me={class:"container"},pe=s("div",{class:"row"},[s("h1",null,"Administration console configuration"),s("br")],-1),ge={class:"box"},ve=s("span",{class:"bi bi-arrows-expand"}," Device signing",-1),we=[ve],Se=s("span",{class:"bi bi-arrows-expand"}," Device revoking",-1),ke=[Se],fe=s("span",{class:"bi bi-arrows-expand"}," SSH configuration",-1),Ke=[fe],Pe=s("span",{class:"bi bi-arrows-expand"}," PKI configuration",-1),xe=[Pe],$e={key:0,class:"row"},Ce=s("h3",null,"USB device signing",-1),Ie={class:"col-sm"},De={key:1,class:"row"},Fe=s("h3",null,"USB device revoking",-1),He={class:"col-sm"},Re={key:2,class:"row"},Ue=s("h3",null,"SSH configuration",-1),Ee={class:"col-sm"},qe={class:"col-sm"},Be={key:3,class:"row"},Ve=s("h3",null,"PKI configuration",-1),Ne={class:"col-sm"},Ae={class:"col-sm"};function Le(r,t,u,m,e,l){const o=h("NavBar"),f=h("SignKey"),K=h("RevokeDevice"),P=h("SSHKeys"),x=h("DisplaySSHConfig"),$=h("SigningKeys"),C=h("DisplaySigningConfig");return n(),i(k,null,[b(o),s("div",me,[pe,s("div",ge,[s("button",{class:"btn btn-info btn-lg shadow",onClick:t[0]||(t[0]=S=>{l.flush(),e.ShowSign=!e.ShowSign})},we),s("button",{class:"btn btn-info btn-lg shadow",onClick:t[1]||(t[1]=S=>{l.flush(),e.ShowRevoke=!e.ShowRevoke})},ke),s("button",{class:"btn btn-info btn-lg shadow",onClick:t[2]||(t[2]=S=>{l.flush(),e.ShowSSH=!e.ShowSSH})},Ke),s("button",{class:"btn btn-info btn-lg shadow",onClick:t[3]||(t[3]=S=>{l.flush(),e.ShowPKI=!e.ShowPKI})},xe)]),e.ShowSign?(n(),i("div",$e,[Ce,s("div",Ie,[b(f)])])):a("",!0),e.ShowRevoke?(n(),i("div",De,[Fe,s("div",He,[b(K)])])):a("",!0),e.ShowSSH?(n(),i("div",Re,[Ue,s("div",Ee,[b(P)]),s("div",qe,[b(x)])])):a("",!0),e.ShowPKI?(n(),i("div",Be,[Ve,s("div",Ne,[b($)]),s("div",Ae,[b(C)])])):a("",!0)])],64)}const Me=y(ye,[["render",Le]]);export{Me as default};