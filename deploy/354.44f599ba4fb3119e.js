"use strict";(self.webpackChunktp05_dubocage_julien=self.webpackChunktp05_dubocage_julien||[]).push([[354],{4354:(f,p,o)=>{o.r(p),o.d(p,{CartModule:()=>C});var a=o(6895),s=o(3074),d=o(6610),t=o(8274),l=o(4318);function u(e,r){1&e&&(t.TgZ(0,"div")(1,"p"),t._uU(2,"Le panier est vide"),t.qZA()())}function m(e,r){if(1&e){const n=t.EpF();t.TgZ(0,"li",4)(1,"div",5)(2,"div",6)(3,"div",7),t._UZ(4,"img",8),t.qZA(),t.TgZ(5,"div",9)(6,"h4",10),t._uU(7),t.qZA(),t.TgZ(8,"p"),t._uU(9),t.qZA(),t.TgZ(10,"p"),t._uU(11),t.qZA(),t.TgZ(12,"p"),t._uU(13),t.qZA(),t.TgZ(14,"button",11),t.NdJ("click",function(){const h=t.CHM(n).index,Z=t.oxw();return t.KtG(Z.removeProductFromCart(h))}),t._UZ(15,"span",12),t._uU(16," Supprimer du panier "),t.qZA()()()()()}if(2&e){const n=r.$implicit;t.xp6(4),t.s9C("src",n.image,t.LSH),t.xp6(3),t.Oqu(n.name),t.xp6(2),t.Oqu(n.description),t.xp6(2),t.hij("Cat\xe9gorie : ",n.category,""),t.xp6(2),t.hij("Prix : ",n.price," \u20ac")}}const g=[{path:"",component:(()=>{class e{constructor(n){this.store=n,this.products$=this.store.select(i=>i.cart.products)}removeProductFromCart(n){this.store.dispatch(new d.m(n))}}return e.\u0275fac=function(n){return new(n||e)(t.Y36(l.yh))},e.\u0275cmp=t.Xpm({type:e,selectors:[["app-cart"]],decls:8,vars:6,consts:[[1,"container"],[4,"ngIf"],[1,"media-list"],["class","media",4,"ngFor","ngForOf"],[1,"media"],[1,"panel","panel-default"],[1,"panel-body"],[1,"media-left"],["alt","...",1,"media-object",3,"src"],[1,"media-body"],[1,"media-heading"],["type","button",1,"btn","btn-danger",3,"click"],["aria-hidden","true",1,"glyphicon","glyphicon-remove"]],template:function(n,i){if(1&n&&(t.TgZ(0,"div",0)(1,"h2"),t._uU(2,"Mon super panier"),t.qZA(),t.YNc(3,u,3,0,"div",1),t.ALo(4,"async"),t.TgZ(5,"ul",2),t.YNc(6,m,17,5,"li",3),t.ALo(7,"async"),t.qZA()()),2&n){let c;t.xp6(3),t.Q6J("ngIf",0==(null==(c=t.lcZ(4,2,i.products$))?null:c.length)),t.xp6(3),t.Q6J("ngForOf",t.lcZ(7,4,i.products$))}},dependencies:[a.sg,a.O5,a.Ov],styles:[".container[_ngcontent-%COMP%]{margin-bottom:2.5em}img[_ngcontent-%COMP%]{max-width:128px;max-height:128px}.media-list[_ngcontent-%COMP%]{margin-top:2em}.media-heading[_ngcontent-%COMP%]{font-weight:700}"]}),e})()}];let C=(()=>{class e{}return e.\u0275fac=function(n){return new(n||e)},e.\u0275mod=t.oAB({type:e}),e.\u0275inj=t.cJS({imports:[a.ez,s.Bz.forChild(g)]}),e})()}}]);