"use strict";(self.webpackChunktp06_dubocage_julien=self.webpackChunktp06_dubocage_julien||[]).push([[145],{6145:(et,y,a)=>{a.r(y),a.d(y,{CatalogueModule:()=>tt});var h=a(6895),g=a(3074),m=a(4004),Z=a(6610),t=a(8274),P=a(2340),T=a(529);let v=(()=>{class n{constructor(e){this.http=e,this.env=P.N}getProducts(){return this.http.get(this.env.apiBaseUrl+"/products")}getProduct(e){return this.http.get(this.env.apiBaseUrl+`/product/${e}`)}}return n.\u0275fac=function(e){return new(e||n)(t.LFG(T.eN))},n.\u0275prov=t.Yz7({token:n,factory:n.\u0275fac,providedIn:"root"}),n})();var x=a(5519),O=a(8421),M=a(9751),U=a(5577),E=a(1144),u=a(576),L=a(3268);const b=["addListener","removeListener"],F=["addEventListener","removeEventListener"],j=["on","off"];function f(n,i,e,o){if((0,u.m)(e)&&(o=e,e=void 0),o)return f(n,i,e).pipe((0,L.Z)(o));const[r,c]=function I(n){return(0,u.m)(n.addEventListener)&&(0,u.m)(n.removeEventListener)}(n)?F.map(s=>l=>n[s](i,l,e)):function J(n){return(0,u.m)(n.addListener)&&(0,u.m)(n.removeListener)}(n)?b.map(A(n,i)):function w(n){return(0,u.m)(n.on)&&(0,u.m)(n.off)}(n)?j.map(A(n,i)):[];if(!r&&(0,E.z)(n))return(0,U.z)(s=>f(s,i,e))((0,O.Xf)(n));if(!r)throw new TypeError("Invalid event target");return new M.y(s=>{const l=(...d)=>s.next(1<d.length?d:d[0]);return r(l),()=>c(l)})}function A(n,i){return e=>o=>n[e](i,o)}var R=a(4408);const Y=new(a(7565).v)(R.o);var z=a(4482),G=a(5403),N=a(1884),C=a(4006);const D=["input"],Q=["select"];let K=(()=>{class n{constructor(){this.search=new t.vpe,this.category=new t.vpe,this.reset=new t.vpe}ngAfterViewInit(){this.select.nativeElement.selectedIndex=-1,this.searchField$=f(this.input.nativeElement,"keyup"),this.searchField$.pipe((0,m.U)(e=>e.target.value),function H(n,i=Y){return(0,z.e)((e,o)=>{let r=null,c=null,s=null;const l=()=>{if(r){r.unsubscribe(),r=null;const p=c;c=null,o.next(p)}};function d(){const p=s+n,S=i.now();if(S<p)return r=this.schedule(void 0,p-S),void o.add(r);l()}e.subscribe((0,G.x)(o,p=>{c=p,s=i.now(),r||(r=i.schedule(d,n),o.add(r))},()=>{l(),o.complete()},void 0,()=>{c=r=null}))})}(300),(0,N.x)()).subscribe(e=>this.search.emit(e))}changeCategory(e){this.category.emit(e)}clickReset(){this.input.nativeElement.value="",this.select.nativeElement.selectedIndex=-1,this.reset.emit()}}return n.\u0275fac=function(e){return new(e||n)},n.\u0275cmp=t.Xpm({type:n,selectors:[["app-search"]],viewQuery:function(e,o){if(1&e&&(t.Gf(D,7),t.Gf(Q,7)),2&e){let r;t.iGM(r=t.CRH())&&(o.input=r.first),t.iGM(r=t.CRH())&&(o.select=r.first)}},outputs:{search:"search",category:"category",reset:"reset"},decls:13,vars:0,consts:[["id","search-container"],["id","category",1,"form-control",3,"change"],["select",""],["value","Livre"],["value","Jeu"],[1,"input-group"],["type","text","placeholder","Rechercher...",1,"form-control"],["input",""],[1,"input-group-btn"],["type","button",1,"btn","btn-danger",3,"click"],["aria-hidden","true",1,"glyphicon","glyphicon-remove"]],template:function(e,o){if(1&e){const r=t.EpF();t.TgZ(0,"div",0)(1,"select",1,2),t.NdJ("change",function(){t.CHM(r);const s=t.MAs(2);return t.KtG(o.changeCategory(s.value))}),t.TgZ(3,"option",3),t._uU(4,"Livre"),t.qZA(),t.TgZ(5,"option",4),t._uU(6,"Jeu"),t.qZA()(),t.TgZ(7,"div",5),t._UZ(8,"input",6,7),t.TgZ(10,"div",8)(11,"button",9),t.NdJ("click",function(){return o.clickReset()}),t._UZ(12,"span",10),t.qZA()()()()}},dependencies:[C.YN,C.Kr],styles:["#category[_ngcontent-%COMP%]{max-width:8%;margin-right:10px}#search-container[_ngcontent-%COMP%]{display:flex}.input-group[_ngcontent-%COMP%]{width:100%}"]}),n})();const $=function(n){return["/catalogue/product/",n]};function B(n,i){if(1&n){const e=t.EpF();t.TgZ(0,"li",4)(1,"div",5)(2,"div",6)(3,"div",7),t._UZ(4,"img",8),t.qZA(),t.TgZ(5,"div",9)(6,"h4",10)(7,"a",11),t._uU(8),t.qZA()(),t.TgZ(9,"p"),t._uU(10),t.qZA(),t.TgZ(11,"p"),t._uU(12),t.qZA(),t.TgZ(13,"p"),t._uU(14),t.qZA(),t.TgZ(15,"button",12),t.NdJ("click",function(){const c=t.CHM(e).$implicit,s=t.oxw();return t.KtG(s.addProductToCart(c))}),t._UZ(16,"span",13),t._uU(17," Ajouter au panier "),t.qZA()()()()()}if(2&n){const e=i.$implicit;t.xp6(4),t.s9C("src",e.image,t.LSH),t.xp6(3),t.Q6J("routerLink",t.VKq(6,$,e.id)),t.xp6(1),t.Oqu(e.name),t.xp6(2),t.Oqu(e.description),t.xp6(2),t.hij("Cat\xe9gorie : ",e.category,""),t.xp6(2),t.hij("Prix : ",e.price," \u20ac")}}let X=(()=>{class n{constructor(e,o){this.catalogueService=e,this.store=o,this.products=[],this.query="",this.category=""}ngOnInit(){this.resetSearch()}addProductToCart(e){this.store.dispatch(new Z.R(e))}onSearch(e){this.query=e,this.handleSearch()}onCategoryChange(e){this.category=e,this.handleSearch()}handleSearch(){this.catalogueService.getProducts().pipe((0,m.U)(e=>e.filter(o=>o.name.toLowerCase().includes(this.query.toLowerCase()))),(0,m.U)(e=>e.filter(o=>!this.category||o.category===this.category))).subscribe(e=>this.products=e)}OnReset(){this.resetSearch()}resetSearch(){this.category="",this.query="",this.catalogueService.getProducts().subscribe(e=>this.products=e)}}return n.\u0275fac=function(e){return new(e||n)(t.Y36(v),t.Y36(x.yh))},n.\u0275cmp=t.Xpm({type:n,selectors:[["app-catalogue"]],decls:6,vars:1,consts:[[1,"container"],[3,"reset","search","category"],[1,"media-list"],["class","media",4,"ngFor","ngForOf"],[1,"media"],[1,"panel","panel-default"],[1,"panel-body"],[1,"media-left"],["alt","...",1,"media-object",3,"src"],[1,"media-body"],[1,"media-heading"],[3,"routerLink"],["type","button",1,"btn","btn-default",3,"click"],["aria-hidden","true",1,"glyphicon","glyphicon-shopping-cart"]],template:function(e,o){1&e&&(t.TgZ(0,"div",0)(1,"h2"),t._uU(2,"Mon super catalogue"),t.qZA(),t.TgZ(3,"app-search",1),t.NdJ("reset",function(){return o.OnReset()})("search",function(c){return o.onSearch(c)})("category",function(c){return o.onCategoryChange(c)}),t.qZA(),t.TgZ(4,"ul",2),t.YNc(5,B,18,8,"li",3),t.qZA()()),2&e&&(t.xp6(5),t.Q6J("ngForOf",o.products))},dependencies:[h.sg,g.yS,K],styles:[".container[_ngcontent-%COMP%]{margin-bottom:2.5em}img[_ngcontent-%COMP%]{max-width:128px;max-height:128px}.media-list[_ngcontent-%COMP%]{margin-top:2em}.media-heading[_ngcontent-%COMP%]{font-weight:700}"]}),n})();function V(n,i){if(1&n){const e=t.EpF();t.TgZ(0,"div",2)(1,"div",3)(2,"h3",4),t._uU(3),t.qZA()(),t.TgZ(4,"div",5)(5,"div",6),t._UZ(6,"img",7),t.qZA(),t.TgZ(7,"div",8)(8,"p"),t._uU(9),t.qZA(),t.TgZ(10,"p"),t._uU(11),t.qZA(),t.TgZ(12,"p"),t._uU(13),t.qZA(),t.TgZ(14,"p"),t._uU(15),t.qZA(),t.TgZ(16,"button",9),t.NdJ("click",function(){t.CHM(e);const r=t.oxw();return t.KtG(r.addProductToCart(r.product))}),t._UZ(17,"span",10),t._uU(18," Ajouter au panier "),t.qZA()()()()}if(2&n){const e=t.oxw();t.xp6(3),t.Oqu(e.product.name),t.xp6(3),t.s9C("src",e.product.image,t.LSH),t.xp6(3),t.Oqu(e.product.description),t.xp6(2),t.hij("Cat\xe9gorie : ",e.product.category,""),t.xp6(2),t.hij("Prix : ",e.product.price," \u20ac"),t.xp6(2),t.Oqu(e.product.summary)}}let W=(()=>{class n{constructor(e,o,r){this.route=e,this.catalogueService=o,this.store=r}ngOnInit(){this.catalogueService.getProduct(this.route.snapshot.params.id).subscribe(o=>this.product=o)}addProductToCart(e){this.store.dispatch(new Z.R(e))}}return n.\u0275fac=function(e){return new(e||n)(t.Y36(g.gz),t.Y36(v),t.Y36(x.yh))},n.\u0275cmp=t.Xpm({type:n,selectors:[["app-product-detail"]],decls:2,vars:1,consts:[[1,"container"],["class","panel panel-default",4,"ngIf"],[1,"panel","panel-default"],[1,"panel-heading"],[1,"panel-title"],[1,"panel-body"],[1,"media-left"],["alt","...",1,"media-object",3,"src"],[1,"media-body"],["type","button",1,"btn","btn-primary",3,"click"],["aria-hidden","true",1,"glyphicon","glyphicon-shopping-cart"]],template:function(e,o){1&e&&(t.TgZ(0,"div",0),t.YNc(1,V,19,6,"div",1),t.qZA()),2&e&&(t.xp6(1),t.Q6J("ngIf",o.product))},dependencies:[h.O5],styles:["img[_ngcontent-%COMP%]{max-width:384px;max-height:384px}.panel-title[_ngcontent-%COMP%]{font-weight:700;font-size:large}.panel-body[_ngcontent-%COMP%]{font-size:medium}button[_ngcontent-%COMP%]{width:200px;height:35px}"]}),n})();var _=a(1325);const k=[{path:"",component:X},{path:"product/:id",component:W}];let tt=(()=>{class n{}return n.\u0275fac=function(e){return new(e||n)},n.\u0275mod=t.oAB({type:n}),n.\u0275inj=t.cJS({providers:[v,{provide:T.TP,useClass:_.O,multi:!0}],imports:[h.ez,g.Bz.forChild(k),C.u5]}),n})()}}]);