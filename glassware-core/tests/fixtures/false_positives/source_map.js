// FALSE POSITIVE TEST FIXTURE — Minified JS with source map
// This file should produce ZERO findings
// Pattern: Minified code with base64 source map data URI
// NO eval, NO Function constructor, NO dynamic execution

(function(){function a(a,b){return a+b}function b(a,b){return a-b}function c(a,b){return a*b}function d(a,b){if(0===b)throw new Error("Division by zero");return a/b}window.MathUtils={add:a,subtract:b,multiply:c,divide:d}})();
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoibWF0aC11dGlscy5taW4uanMiLCJzb3VyY2VzIjpbIm1hdGgtdXRpbHMuanMiXSwibmFtZXMiOlsiYWRkIiwic3VidHJhY3QiLCJtdWx0aXBseSIsImRpdmlkZSIsIk1hdGhVdGlscyJdLCJtYXBwaW5ncyI6IkFBQUEsU0FBU0EsRUFBWSxDQUFDLEVBQUVDLEVBQVksRUFBRSxPQUFPQSxDQUFDLEdBQUdDLEVBQUUsRUFBRSxTQUFTQyxFQUFZLENBQUMsRUFBRSIsInNvdXJjZXNDb250ZW50IjpbImZ1bmN0aW9uIGFkZChhLCBiKSB7IHJldHVybiBhICsgYjsgfVxuXG5mdW5jdGlvbiBzdWJ0cmFjdChhLCBiKSB7IHJldHVybiBhIC0gYjsgfVxuXG5mdW5jdGlvbiBtdWx0aXBseShhLCBiKSB7IHJldHVybiBhICogYjsgfVxuXG5mdW5jdGlvbiBkaXZpZGUoYSwgYikge1xuICBpZiAoYiA9PT0gMCkgdGhyb3cgbmV3IEVycm9yKCdEaXZpc2lvbiBieSB6ZXJvJyk7XG4gIHJldHVybiBhIC8gYjtcbn1cblxuZ2xvYmFsLk1hdGhVdGlscyA9IHsgYWRkLCBzdWJ0cmFjdCwgbXVsdGlwbHksIGRpdmlkZSB9OyJdfQ==
