/******/ (function(modules) { // webpackBootstrap
/******/ 	// The module cache
/******/ 	var installedModules = {};

/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {

/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId])
/******/ 			return installedModules[moduleId].exports;

/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			exports: {},
/******/ 			id: moduleId,
/******/ 			loaded: false
/******/ 		};

/******/ 		// Execute the module function
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);

/******/ 		// Flag the module as loaded
/******/ 		module.loaded = true;

/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}


/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = modules;

/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = installedModules;

/******/ 	// __webpack_public_path__
/******/ 	__webpack_require__.p = "";

/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(0);
/******/ })
/************************************************************************/
/******/ ([
/* 0 */
/***/ function(module, exports) {

	/**
	 * Toolkit JavaScript
	 */

	'use strict';

	/*
	window.onload = function() {
	var width = Math.max(document.documentElement.clientWidth, window.innerWidth || 0);
	 if (width < 500){
	 	var element = document.getElementById("logo-header");
		element.scrollIntoView({behavior:'smooth'});
	 }


	};
	*/

	function animate(elem, style, unit, from, to, time, prop) {
	    if (!elem) {
	        return;
	    }
	    var start = new Date().getTime(),
	        timer = setInterval(function () {
	        var step = Math.min(1, (new Date().getTime() - start) / time);
	        if (prop) {
	            elem[style] = from + step * (to - from) + unit;
	        } else {
	            elem.style[style] = from + step * (to - from) + unit;
	        }
	        if (step === 1) {
	            clearInterval(timer);
	        }
	    }, 25);
	    if (prop) {
	        elem[style] = from + unit;
	    } else {
	        elem.style[style] = from + unit;
	    }
	}

	window.onload = function () {

	    var width = Math.max(document.documentElement.clientWidth, window.innerWidth || 0);
	    if (width < 991) {

	        var target = document.getElementById("logo-header");
	        animate(document.scrollingElement || document.documentElement, "scrollTop", "", 0, target.offsetTop, 400, true);
	    }
	};
	/*
	window.onresize = resize;

	function resize()
	{
	  var width = Math.max(document.documentElement.clientWidth, window.innerWidth || 0);
	  var topheight = document.getElementById('dark-back').clientHeight;
	  console.log(width);
	  if(width>991){
	    document.getElementById("logo-header").style.marginTop = "0";
	  }
	  else{
	    document.getElementById("logo-header").style.marginTop = topheight+"px";
	  }
	}
	*/

/***/ }
/******/ ]);