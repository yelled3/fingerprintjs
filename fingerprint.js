/*
* fingerprintJS 0.5.4 - Fast browser fingerprint library
* https://github.com/Valve/fingerprintjs
* Copyright (c) 2013 Valentin Vasilyev (valentin.vasilyev@outlook.com)
* Licensed under the MIT (http://www.opensource.org/licenses/mit-license.php) license.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
* THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

;(function (name, context, definition) {
  if (typeof module !== 'undefined' && module.exports) { module.exports = definition(); }
  else if (typeof define === 'function' && define.amd) { define(definition); }
  else { context[name] = definition(); }
})('Fingerprint', this, function () {
  'use strict';

  var Fingerprint = function (options) {
    var nativeForEach, nativeMap;
    nativeForEach = Array.prototype.forEach;
    nativeMap = Array.prototype.map;

    this.each = function (obj, iterator, context) {
      if (obj === null) {
        return;
      }
      if (nativeForEach && obj.forEach === nativeForEach) {
        obj.forEach(iterator, context);
      } else if (obj.length === +obj.length) {
        for (var i = 0, l = obj.length; i < l; i++) {
          if (iterator.call(context, obj[i], i, obj) === {}) return;
        }
      } else {
        for (var key in obj) {
          if (obj.hasOwnProperty(key)) {
            if (iterator.call(context, obj[key], key, obj) === {}) return;
          }
        }
      }
    };

    this.map = function(obj, iterator, context) {
      var results = [];
      // Not using strict equality so that this acts as a
      // shortcut to checking for `null` and `undefined`.
      if (obj == null) return results;
      if (nativeMap && obj.map === nativeMap) return obj.map(iterator, context);
      this.each(obj, function(value, index, list) {
        results[results.length] = iterator.call(context, value, index, list);
      });
      return results;
    };

    if (typeof options == 'object'){
      this.hasher = options.hasher;
      this.screen_resolution = options.screen_resolution;
      this.screen_orientation = options.screen_orientation;
      this.canvas = options.canvas;
      this.ie_activex = options.ie_activex;
    } else if(typeof options == 'function'){
      this.hasher = options;
    }
  };

  Fingerprint.prototype = {
    get: function(){
      var keys = [];
      keys.push(navigator.userAgent);
      keys.push(navigator.language);
      keys.push(screen.colorDepth);
      if (this.screen_resolution) {
        var resolution = this.getScreenResolution();
        if (typeof resolution !== 'undefined'){ // headless browsers, such as phantomjs
          keys.push(this.getScreenResolution().join('x'));
        }
      }
      keys.push(new Date().getTimezoneOffset());
      keys.push(this.hasSessionStorage());
      keys.push(this.hasLocalStorage());
      keys.push(!!window.indexedDB);
      //body might not be defined at this point or removed programmatically
      if(document.body){
        keys.push(typeof(document.body.addBehavior));
      } else {
        keys.push(typeof undefined);
      }
      keys.push(typeof(window.openDatabase));
      keys.push(navigator.cpuClass);
      keys.push(navigator.platform);
      keys.push(navigator.doNotTrack);
      keys.push(this.getPluginsString());
      if(this.canvas && this.isCanvasSupported()){
        keys.push(this.getCanvasFingerprint());
      }
      if(this.hasher){
        return this.hasher(keys.join('~~~'), 31);
      } else {
        return this.x64hash128(keys.join("~~~"), 31);
      }
    },


    /// MurmurHash3 related functions

    //
    // Given two 64bit ints (as an array of two 32bit ints) returns the two
    // added together as a 64bit int (as an array of two 32bit ints).
    //
    x64Add: function(m, n) {
      m = [m[0] >>> 16, m[0] & 0xffff, m[1] >>> 16, m[1] & 0xffff];
      n = [n[0] >>> 16, n[0] & 0xffff, n[1] >>> 16, n[1] & 0xffff];
      var o = [0, 0, 0, 0];
      o[3] += m[3] + n[3];
      o[2] += o[3] >>> 16;
      o[3] &= 0xffff;
      o[2] += m[2] + n[2];
      o[1] += o[2] >>> 16;
      o[2] &= 0xffff;
      o[1] += m[1] + n[1];
      o[0] += o[1] >>> 16;
      o[1] &= 0xffff;
      o[0] += m[0] + n[0];
      o[0] &= 0xffff;
      return [(o[0] << 16) | o[1], (o[2] << 16) | o[3]];
    },

    //
    // Given two 64bit ints (as an array of two 32bit ints) returns the two
    // multiplied together as a 64bit int (as an array of two 32bit ints).
    //
    x64Multiply: function(m, n) {
      m = [m[0] >>> 16, m[0] & 0xffff, m[1] >>> 16, m[1] & 0xffff];
      n = [n[0] >>> 16, n[0] & 0xffff, n[1] >>> 16, n[1] & 0xffff];
      var o = [0, 0, 0, 0];
      o[3] += m[3] * n[3];
      o[2] += o[3] >>> 16;
      o[3] &= 0xffff;
      o[2] += m[2] * n[3];
      o[1] += o[2] >>> 16;
      o[2] &= 0xffff;
      o[2] += m[3] * n[2];
      o[1] += o[2] >>> 16;
      o[2] &= 0xffff;
      o[1] += m[1] * n[3];
      o[0] += o[1] >>> 16;
      o[1] &= 0xffff;
      o[1] += m[2] * n[2];
      o[0] += o[1] >>> 16;
      o[1] &= 0xffff;
      o[1] += m[3] * n[1];
      o[0] += o[1] >>> 16;
      o[1] &= 0xffff;
      o[0] += (m[0] * n[3]) + (m[1] * n[2]) + (m[2] * n[1]) + (m[3] * n[0]);
      o[0] &= 0xffff;
      return [(o[0] << 16) | o[1], (o[2] << 16) | o[3]];
    },
    //
    // Given a 64bit int (as an array of two 32bit ints) and an int
    // representing a number of bit positions, returns the 64bit int (as an
    // array of two 32bit ints) rotated left by that number of positions.
    //
    x64Rotl: function(m, n) {
      n %= 64;
      if (n === 32) {
        return [m[1], m[0]];
      }
      else if (n < 32) {
        return [(m[0] << n) | (m[1] >>> (32 - n)), (m[1] << n) | (m[0] >>> (32 - n))];
      }
      else {
        n -= 32;
        return [(m[1] << n) | (m[0] >>> (32 - n)), (m[0] << n) | (m[1] >>> (32 - n))];
      }
    },
    //
    // Given a 64bit int (as an array of two 32bit ints) and an int
    // representing a number of bit positions, returns the 64bit int (as an
    // array of two 32bit ints) shifted left by that number of positions.
    //
    x64LeftShift: function(m, n) {
      n %= 64;
      if (n === 0) {
        return m;
      }
      else if (n < 32) {
        return [(m[0] << n) | (m[1] >>> (32 - n)), m[1] << n];
      }
      else {
        return [m[1] << (n - 32), 0];
      }
    },
    //
    // Given two 64bit ints (as an array of two 32bit ints) returns the two
    // xored together as a 64bit int (as an array of two 32bit ints).
    //
    x64Xor: function(m, n) {
      return [m[0] ^ n[0], m[1] ^ n[1]];
    },
    //
    // Given a block, returns murmurHash3's final x64 mix of that block.
    // (`[0, h[0] >>> 1]` is a 33 bit unsigned right shift. This is the
    // only place where we need to right shift 64bit ints.)
    //
    x64Fmix: function(h) {
      h = this.x64Xor(h, [0, h[0] >>> 1]);
      h = this.x64Multiply(h, [0xff51afd7, 0xed558ccd]);
      h = this.x64Xor(h, [0, h[0] >>> 1]);
      h = this.x64Multiply(h, [0xc4ceb9fe, 0x1a85ec53]);
      h = this.x64Xor(h, [0, h[0] >>> 1]);
      return h;
    },

    //
    // Given a string and an optional seed as an int, returns a 128 bit
    // hash using the x64 flavor of MurmurHash3, as an unsigned hex.
    //
    x64hash128: function (key, seed) {
      key = key || "";
      seed = seed || 0;
      var remainder = key.length % 16;
      var bytes = key.length - remainder;
      var h1 = [0, seed];
      var h2 = [0, seed];
      var k1 = [0, 0];
      var k2 = [0, 0];
      var c1 = [0x87c37b91, 0x114253d5];
      var c2 = [0x4cf5ad43, 0x2745937f];
      for (var i = 0; i < bytes; i = i + 16) {
        k1 = [((key.charCodeAt(i + 4) & 0xff)) | ((key.charCodeAt(i + 5) & 0xff) << 8) | ((key.charCodeAt(i + 6) & 0xff) << 16) | ((key.charCodeAt(i + 7) & 0xff) << 24), ((key.charCodeAt(i) & 0xff)) | ((key.charCodeAt(i + 1) & 0xff) << 8) | ((key.charCodeAt(i + 2) & 0xff) << 16) | ((key.charCodeAt(i + 3) & 0xff) << 24)];
        k2 = [((key.charCodeAt(i + 12) & 0xff)) | ((key.charCodeAt(i + 13) & 0xff) << 8) | ((key.charCodeAt(i + 14) & 0xff) << 16) | ((key.charCodeAt(i + 15) & 0xff) << 24), ((key.charCodeAt(i + 8) & 0xff)) | ((key.charCodeAt(i + 9) & 0xff) << 8) | ((key.charCodeAt(i + 10) & 0xff) << 16) | ((key.charCodeAt(i + 11) & 0xff) << 24)];
        k1 = this.x64Multiply(k1, c1);
        k1 = this.x64Rotl(k1, 31);
        k1 = this.x64Multiply(k1, c2);
        h1 = this.x64Xor(h1, k1);
        h1 = this.x64Rotl(h1, 27);
        h1 = this.x64Add(h1, h2);
        h1 = this.x64Add(this.x64Multiply(h1, [0, 5]), [0, 0x52dce729]);
        k2 = this.x64Multiply(k2, c2);
        k2 = this.x64Rotl(k2, 33);
        k2 = this.x64Multiply(k2, c1);
        h2 = this.x64Xor(h2, k2);
        h2 = this.x64Rotl(h2, 31);
        h2 = this.x64Add(h2, h1);
        h2 = this.x64Add(this.x64Multiply(h2, [0, 5]), [0, 0x38495ab5]);
      }
      k1 = [0, 0];
      k2 = [0, 0];
      switch(remainder) {
        case 15:
          k2 = this.x64Xor(k2, this.x64LeftShift([0, key.charCodeAt(i + 14)], 48));
        case 14:
          k2 = this.x64Xor(k2, this.x64LeftShift([0, key.charCodeAt(i + 13)], 40));
        case 13:
          k2 = this.x64Xor(k2, this.x64LeftShift([0, key.charCodeAt(i + 12)], 32));
        case 12:
          k2 = this.x64Xor(k2, this.x64LeftShift([0, key.charCodeAt(i + 11)], 24));
        case 11:
          k2 = this.x64Xor(k2, this.x64LeftShift([0, key.charCodeAt(i + 10)], 16));
        case 10:
          k2 = this.x64Xor(k2, this.x64LeftShift([0, key.charCodeAt(i + 9)], 8));
        case 9:
          k2 = this.x64Xor(k2, [0, key.charCodeAt(i + 8)]);
          k2 = this.x64Multiply(k2, c2);
          k2 = this.x64Rotl(k2, 33);
          k2 = this.x64Multiply(k2, c1);
          h2 = this.x64Xor(h2, k2);
        case 8:
          k1 = this.x64Xor(k1, this.x64LeftShift([0, key.charCodeAt(i + 7)], 56));
        case 7:
          k1 = this.x64Xor(k1, this.x64LeftShift([0, key.charCodeAt(i + 6)], 48));
        case 6:
          k1 = this.x64Xor(k1, this.x64LeftShift([0, key.charCodeAt(i + 5)], 40));
        case 5:
          k1 = this.x64Xor(k1, this.x64LeftShift([0, key.charCodeAt(i + 4)], 32));
        case 4:
          k1 = this.x64Xor(k1, this.x64LeftShift([0, key.charCodeAt(i + 3)], 24));
        case 3:
          k1 = this.x64Xor(k1, this.x64LeftShift([0, key.charCodeAt(i + 2)], 16));
        case 2:
          k1 = this.x64Xor(k1, this.x64LeftShift([0, key.charCodeAt(i + 1)], 8));
        case 1:
          k1 = this.x64Xor(k1, [0, key.charCodeAt(i)]);
          k1 = this.x64Multiply(k1, c1);
          k1 = this.x64Rotl(k1, 31);
          k1 = this.x64Multiply(k1, c2);
          h1 = this.x64Xor(h1, k1);
      }
      h1 = this.x64Xor(h1, [0, key.length]);
      h2 = this.x64Xor(h2, [0, key.length]);
      h1 = this.x64Add(h1, h2);
      h2 = this.x64Add(h2, h1);
      h1 = this.x64Fmix(h1);
      h2 = this.x64Fmix(h2);
      h1 = this.x64Add(h1, h2);
      h2 = this.x64Add(h2, h1);
      return ("00000000" + (h1[0] >>> 0).toString(16)).slice(-8) + ("00000000" + (h1[1] >>> 0).toString(16)).slice(-8) + ("00000000" + (h2[0] >>> 0).toString(16)).slice(-8) + ("00000000" + (h2[1] >>> 0).toString(16)).slice(-8);
    },

    // https://bugzilla.mozilla.org/show_bug.cgi?id=781447
    hasLocalStorage: function () {
      try{
        return !!window.localStorage;
      } catch(e) {
        return true; // SecurityError when referencing it means it exists
      }
    },

    hasSessionStorage: function () {
      try{
        return !!window.sessionStorage;
      } catch(e) {
        return true; // SecurityError when referencing it means it exists
      }
    },

    isCanvasSupported: function () {
      var elem = document.createElement('canvas');
      return !!(elem.getContext && elem.getContext('2d'));
    },

    isIE: function () {
      if(navigator.appName === 'Microsoft Internet Explorer') {
        return true;
      } else if(navigator.appName === 'Netscape' && /Trident/.test(navigator.userAgent)){// IE 11
        return true;
      }
      return false;
    },

    getPluginsString: function () {
      if(this.isIE() && this.ie_activex){
        return this.getIEPluginsString();
      } else {
        return this.getRegularPluginsString();
      }
    },

    getRegularPluginsString: function () {
      return this.map(navigator.plugins, function (p) {
        var mimeTypes = this.map(p, function(mt){
          return [mt.type, mt.suffixes].join('~');
        }).join(',');
        return [p.name, p.description, mimeTypes].join('::');
      }, this).join(';');
    },

    getIEPluginsString: function () {
      if(window.ActiveXObject){
        var names = ['ShockwaveFlash.ShockwaveFlash',//flash plugin
          'AcroPDF.PDF', // Adobe PDF reader 7+
          'PDF.PdfCtrl', // Adobe PDF reader 6 and earlier, brrr
          'QuickTime.QuickTime', // QuickTime
          // 5 versions of real players
          'rmocx.RealPlayer G2 Control',
          'rmocx.RealPlayer G2 Control.1',
          'RealPlayer.RealPlayer(tm) ActiveX Control (32-bit)',
          'RealVideo.RealVideo(tm) ActiveX Control (32-bit)',
          'RealPlayer',
          'SWCtl.SWCtl', // ShockWave player
          'WMPlayer.OCX', // Windows media player
          'AgControl.AgControl', // Silverlight
          'Skype.Detection'];

        // starting to detect plugins in IE
        return this.map(names, function(name){
          try{
            new ActiveXObject(name);
            return name;
          } catch(e){
            return null;
          }
        }).join(';');
      } else {
        return ""; // behavior prior version 0.5.0, not breaking backwards compat.
      }
    },

    getScreenResolution: function () {
      var resolution;
       if(this.screen_orientation){
         resolution = (screen.height > screen.width) ? [screen.height, screen.width] : [screen.width, screen.height];
       }else{
         resolution = [screen.height, screen.width];
       }
       return resolution;
    },

    getCanvasFingerprint: function () {
      var canvas = document.createElement('canvas');
      var ctx = canvas.getContext('2d');
      // https://www.browserleaks.com/canvas#how-does-it-work
      var txt = 'http://valve.github.io';
      ctx.textBaseline = "top";
      ctx.font = "14px 'Arial'";
      ctx.textBaseline = "alphabetic";
      ctx.fillStyle = "#f60";
      ctx.fillRect(125,1,62,20);
      ctx.fillStyle = "#069";
      ctx.fillText(txt, 2, 15);
      ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
      ctx.fillText(txt, 4, 17);
      return canvas.toDataURL();
    }
  };


  return Fingerprint;

});
