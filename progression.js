/* Optional local completion marks. Every lesson is accessible immediately. */
(function(root){
 const groups=[['enumeration','rate-limit','email-flood'],['idor','edge403'],['reflected-xss','dom-xss'],['csrf','cors'],['open-redirect','ssrf'],['api-keys','exposed-files']];
 class CourseProgress {
  constructor(saved={}){this.finished={};for(const id of groups.flat())if(saved?.[id]===true||saved?.[id]===100)this.finished[id]=true;}
  level(id){return groups.findIndex(group=>group.includes(id))+1;}
  canAccess(id){return this.level(id)>0;}
  complete(id){if(!this.canAccess(id))return false;const fresh=!this.finished[id];this.finished[id]=true;return fresh;}
  reset(){this.finished={};}
 }
 const api={CourseProgress,groups};
 if(typeof module!=='undefined'&&module.exports)module.exports=api;else root.Course=api;
})(globalThis);
