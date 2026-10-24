/* Educational local progress; intentionally not a secure examination service. */
(function(root){
 const groups=[['enumeration','rate-limit','email-flood'],['idor','edge403'],['reflected-xss','dom-xss'],['csrf','cors'],['open-redirect','ssrf'],['api-keys','exposed-files']];
 class CourseProgress {
  constructor(saved={}){this.awards={};for(const id of groups.flat())if(saved?.[id]===100)this.awards[id]=100;}
  get points(){return Object.values(this.awards).reduce((a,b)=>a+b,0);}
  level(id){return groups.findIndex(group=>group.includes(id))+1;}
  canAccess(id){const level=this.level(id);return level>0&&groups.slice(0,level-1).flat().every(key=>this.awards[key]===100);}
  complete(id){if(!this.canAccess(id))return false;const fresh=!this.awards[id];this.awards[id]=100;return fresh;}
  reset(){this.awards={};}
 }
 const api={CourseProgress,groups};
 if(typeof module!=='undefined'&&module.exports)module.exports=api;else root.Course=api;
})(globalThis);
