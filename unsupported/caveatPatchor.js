/* MD5 LIB */
/*
 * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
 * Digest Algorithm, as defined in RFC 1321.
 * Copyright (C) Paul Johnston 1999 - 2000.
 * Updated by Greg Holt 2000 - 2001.
 * See http://pajhome.org.uk/site/legal.html for details.
 */

/*
 * Convert a 32-bit number to a hex string with ls-byte first
 */
var hex_chr = "0123456789abcdef";
function rhex(num)
{
  str = "";
  for(j = 0; j <= 3; j++)
    str += hex_chr.charAt((num >> (j * 8 + 4)) & 0x0F) +
           hex_chr.charAt((num >> (j * 8)) & 0x0F);
  return str;
}

/*
 * Convert a string to a sequence of 16-word blocks, stored as an array.
 * Append padding bits and the length, as described in the MD5 standard.
 */
function str2blks_MD5(str)
{
  nblk = ((str.length + 8) >> 6) + 1;
  blks = new Array(nblk * 16);
  for(i = 0; i < nblk * 16; i++) blks[i] = 0;
  for(i = 0; i < str.length; i++)
    blks[i >> 2] |= str.charCodeAt(i) << ((i % 4) * 8);
  blks[i >> 2] |= 0x80 << ((i % 4) * 8);
  blks[nblk * 16 - 2] = str.length * 8;
  return blks;
}

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */
function add(x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * Bitwise rotate a 32-bit number to the left
 */
function rol(num, cnt)
{
  return (num << cnt) | (num >>> (32 - cnt));
}

/*
 * These functions implement the basic operation for each round of the
 * algorithm.
 */
function cmn(q, a, b, x, s, t)
{
  return add(rol(add(add(a, q), add(x, t)), s), b);
}
function ff(a, b, c, d, x, s, t)
{
  return cmn((b & c) | ((~b) & d), a, b, x, s, t);
}
function gg(a, b, c, d, x, s, t)
{
  return cmn((b & d) | (c & (~d)), a, b, x, s, t);
}
function hh(a, b, c, d, x, s, t)
{
  return cmn(b ^ c ^ d, a, b, x, s, t);
}
function ii(a, b, c, d, x, s, t)
{
  return cmn(c ^ (b | (~d)), a, b, x, s, t);
}

/*
 * Take a string and return the hex representation of its MD5.
 */
function calcMD5(str)
{
  x = str2blks_MD5(str);
  a =  1732584193;
  b = -271733879;
  c = -1732584194;
  d =  271733878;

  for(i = 0; i < x.length; i += 16)
  {
    olda = a;
    oldb = b;
    oldc = c;
    oldd = d;

    a = ff(a, b, c, d, x[i+ 0], 7 , -680876936);
    d = ff(d, a, b, c, x[i+ 1], 12, -389564586);
    c = ff(c, d, a, b, x[i+ 2], 17,  606105819);
    b = ff(b, c, d, a, x[i+ 3], 22, -1044525330);
    a = ff(a, b, c, d, x[i+ 4], 7 , -176418897);
    d = ff(d, a, b, c, x[i+ 5], 12,  1200080426);
    c = ff(c, d, a, b, x[i+ 6], 17, -1473231341);
    b = ff(b, c, d, a, x[i+ 7], 22, -45705983);
    a = ff(a, b, c, d, x[i+ 8], 7 ,  1770035416);
    d = ff(d, a, b, c, x[i+ 9], 12, -1958414417);
    c = ff(c, d, a, b, x[i+10], 17, -42063);
    b = ff(b, c, d, a, x[i+11], 22, -1990404162);
    a = ff(a, b, c, d, x[i+12], 7 ,  1804603682);
    d = ff(d, a, b, c, x[i+13], 12, -40341101);
    c = ff(c, d, a, b, x[i+14], 17, -1502002290);
    b = ff(b, c, d, a, x[i+15], 22,  1236535329);

    a = gg(a, b, c, d, x[i+ 1], 5 , -165796510);
    d = gg(d, a, b, c, x[i+ 6], 9 , -1069501632);
    c = gg(c, d, a, b, x[i+11], 14,  643717713);
    b = gg(b, c, d, a, x[i+ 0], 20, -373897302);
    a = gg(a, b, c, d, x[i+ 5], 5 , -701558691);
    d = gg(d, a, b, c, x[i+10], 9 ,  38016083);
    c = gg(c, d, a, b, x[i+15], 14, -660478335);
    b = gg(b, c, d, a, x[i+ 4], 20, -405537848);
    a = gg(a, b, c, d, x[i+ 9], 5 ,  568446438);
    d = gg(d, a, b, c, x[i+14], 9 , -1019803690);
    c = gg(c, d, a, b, x[i+ 3], 14, -187363961);
    b = gg(b, c, d, a, x[i+ 8], 20,  1163531501);
    a = gg(a, b, c, d, x[i+13], 5 , -1444681467);
    d = gg(d, a, b, c, x[i+ 2], 9 , -51403784);
    c = gg(c, d, a, b, x[i+ 7], 14,  1735328473);
    b = gg(b, c, d, a, x[i+12], 20, -1926607734);

    a = hh(a, b, c, d, x[i+ 5], 4 , -378558);
    d = hh(d, a, b, c, x[i+ 8], 11, -2022574463);
    c = hh(c, d, a, b, x[i+11], 16,  1839030562);
    b = hh(b, c, d, a, x[i+14], 23, -35309556);
    a = hh(a, b, c, d, x[i+ 1], 4 , -1530992060);
    d = hh(d, a, b, c, x[i+ 4], 11,  1272893353);
    c = hh(c, d, a, b, x[i+ 7], 16, -155497632);
    b = hh(b, c, d, a, x[i+10], 23, -1094730640);
    a = hh(a, b, c, d, x[i+13], 4 ,  681279174);
    d = hh(d, a, b, c, x[i+ 0], 11, -358537222);
    c = hh(c, d, a, b, x[i+ 3], 16, -722521979);
    b = hh(b, c, d, a, x[i+ 6], 23,  76029189);
    a = hh(a, b, c, d, x[i+ 9], 4 , -640364487);
    d = hh(d, a, b, c, x[i+12], 11, -421815835);
    c = hh(c, d, a, b, x[i+15], 16,  530742520);
    b = hh(b, c, d, a, x[i+ 2], 23, -995338651);

    a = ii(a, b, c, d, x[i+ 0], 6 , -198630844);
    d = ii(d, a, b, c, x[i+ 7], 10,  1126891415);
    c = ii(c, d, a, b, x[i+14], 15, -1416354905);
    b = ii(b, c, d, a, x[i+ 5], 21, -57434055);
    a = ii(a, b, c, d, x[i+12], 6 ,  1700485571);
    d = ii(d, a, b, c, x[i+ 3], 10, -1894986606);
    c = ii(c, d, a, b, x[i+10], 15, -1051523);
    b = ii(b, c, d, a, x[i+ 1], 21, -2054922799);
    a = ii(a, b, c, d, x[i+ 8], 6 ,  1873313359);
    d = ii(d, a, b, c, x[i+15], 10, -30611744);
    c = ii(c, d, a, b, x[i+ 6], 15, -1560198380);
    b = ii(b, c, d, a, x[i+13], 21,  1309151649);
    a = ii(a, b, c, d, x[i+ 4], 6 , -145523070);
    d = ii(d, a, b, c, x[i+11], 10, -1120210379);
    c = ii(c, d, a, b, x[i+ 2], 15,  718787259);
    b = ii(b, c, d, a, x[i+ 9], 21, -343485551);

    a = add(a, olda);
    b = add(b, oldb);
    c = add(c, oldc);
    d = add(d, oldd);
  }
  return rhex(a) + rhex(b) + rhex(c) + rhex(d);
}
/* END MD5 LIB */
var displayAvatars1 = false;
var HTML5Audio = true;
var displayAvatars2 = true;

if (displayAvatars2) {

  Object.extend(Campfire.Message.prototype, {
    authorID: function() {
      if (Element.hasClassName(this.element, 'you'))
        return this.chat.userID;

      var idtext = (this.element.className.match(/\s*user_(\d+)\s*/) || [])[1];
      return parseInt(idtext) || 0;
    },

    addAvatar: function() {
      var
        author = this.authorElement(),
        body = this.bodyCell,
        email,
        avatar, name, imgSize = 32, img;

      avatar = author.getAttribute('data-avatar') || 'http://asset1.37img.com/global/missing/avatar.png?r=3';
      if(!avatar||avatar.match(/missing\/avatar\.gif/)) {
        email = author.getAttribute('data-email')
        if (email) {
          var hash = calcMD5(email.trim().toLowerCase())
          avatar = "http://gravatar.com/avatar/"+hash
        } else {
          // avatar = author.getAttribute('data-avatar') || 'http://asset1.37img.com/global/missing/avatar.png?r=3';
          avatar = 'http://globase.heroku.com/redirect/gh.gravatars.' + this.authorID() + '?default=http://github.com/images/gravatars/gravatar-140.png';
        }
      }
      name = '<strong class="authorName">'+author.textContent+'</strong>'

      if (this.actsLikeTextMessage()) {
        name += '<br>'
      } else {
        return;
      }

      img = '<img alt="'+this.author()+'" width="'+imgSize+'" height="'+imgSize+'" class="avatar" src="'+avatar+'">'

      if (author.visible()) {
        author.hide();

        if (body.select('strong.authorName').length === 0) {
          body.insert({top: name});
          if (img)
            author.insert({after: img});
        }
      }
    }
  });

  /* if you can wrap rather than rewrite, use swizzle like this: */
  swizzle(Campfire.Message, {
    setAuthorVisibilityInRelationTo: function($super, message) {
      $super(message);
      this.addAvatar();
    },
    authorElement: function($super) {
        return $super()
    }
  });


  /* defining a new responder is probably the best way to insulate your hacks from Campfire and Propane */
  Campfire.AvatarMangler = Class.create({
      initialize: function(chat) {
          this.chat = chat;

          var messages = this.chat.transcript.messages;
          for (var i = 0; i < messages.length; i++) {
              var message = messages[i];
              message.addAvatar();
          }

          this.chat.layoutmanager.layout();
          this.chat.windowmanager.scrollToBottom();
      },

      onMessagesInserted: function(messages) {
          var scrolledToBottom = this.chat.windowmanager.isScrolledToBottom();

          for (var i = 0; i < messages.length; i++) {
              var message = messages[i];
              message.addAvatar();
          }

          if ((this.chat.windowmanager.getScrollOffset() + this.chat.windowmanager.getWindowHeight()) >=
          (this.chat.windowmanager.getPageHeight() - 400)) {
              setTimeout(
              (function(cfobj) {
                  return function() {
                      cfobj.chat.windowmanager.scrollToBottom();
                  }
              })(this), 500);
          }
      }
  });

  /* Here is how to install your responder into the running chat */
  Campfire.Responders.push("AvatarMangler");
  window.chat.installPropaneResponder("AvatarMangler", "avatarmangler");
}

/*
 *   Display avatars in the chat view - based on code originally by @tmm1
 *   */

if (displayAvatars1) {

    Object.extend(Campfire.Message.prototype, {
        addAvatar: function() {
            if (this.actsLikeTextMessage()) {
                var author = this.authorElement();
                var avatar = '';

                if (author.visible()) {
                    author.hide();
                    if (this.bodyCell.select('strong').length === 0) {
                        this.bodyCell.insert({
                            top: '<strong >' + author.textContent + '</strong><br>'
                        });
                        avatar = author.getAttribute('data-avatar') || 'http://asset1.37img.com/global/missing/avatar.png?r=3';
                        author.insert({
                            after: '<img alt="' + this.author() + '" width="32" height="32" align="top" class="avatar" src="' + avatar + '">'
                        });
                    }
                }
            }
        }
    });

    /* if you can wrap rather than rewrite, use swizzle like this: */
    swizzle(Campfire.Message, {
        setAuthorVisibilityInRelationTo: function($super, message) {
            $super(message);
            this.addAvatar();
        }
    });


    /* defining a new responder is probably the best way to insulate your hacks from Campfire and Propane */
    Campfire.AvatarMangler = Class.create({
        initialize: function(chat) {
            this.chat = chat;

            var messages = this.chat.transcript.messages;
            for (var i = 0; i < messages.length; i++) {
                var message = messages[i];
                message.addAvatar();
            }

            this.chat.layoutmanager.layout();
            this.chat.windowmanager.scrollToBottom();
        },

        onMessagesInserted: function(messages) {
            var scrolledToBottom = this.chat.windowmanager.isScrolledToBottom();

            for (var i = 0; i < messages.length; i++) {
                var message = messages[i];
                message.addAvatar();
            }

            if ((this.chat.windowmanager.getScrollOffset() + this.chat.windowmanager.getWindowHeight()) >=
            (this.chat.windowmanager.getPageHeight() - 400)) {
                setTimeout(
                (function(cfobj) {
                    return function() {
                        cfobj.chat.windowmanager.scrollToBottom();
                    }
                })(this), 500);
            }
        }
    });

    /* Here is how to install your responder into the running chat */
    Campfire.Responders.push("AvatarMangler");
    window.chat.installPropaneResponder("AvatarMangler", "avatarmangler");
}



if (HTML5Audio) {
  Campfire.HTML5Audio = Class.create({
    initialize: function(chat) {
      this.chat = chat;
      var messages = this.chat.transcript.messages;
      for(var i = 0; i < messages.length; i++) {
        this.detectAudio(messages[i], false);
      }
    },

    detectAudio: function(message, autoplay) {
      if (!message.pending() && message.kind === 'text') {
        var links = message.bodyElement().select('a:not(image)');


        if (links.length != 1) return;
        var audio_url = links[0].getAttribute('href');


        var match = audio_url.match(/\.(wav|mp3|m4a)$/);

        if (!match) return;

        var audio = '';
        if (autoplay) {
          audio = '<audio autoplay="autoplay" controls="controls"><source src="' + audio_url + '" /></audio>';
        } else {
          audio = '<audio controls="controls"><source src="' + audio_url + '" /></audio>';
        }

        message.resize((function() {
          message.bodyCell.insert({ bottom: audio });
        }).bind(this));
      }
    },

    onMessagesInsertedBeforeDisplay: function(messages) {
      for (var i = 0; i < messages.length; i++) {
        this.detectAudio(messages[i], true);
      }
    },

    onMessageAccepted: function(message, messageID) {
      this.detectAudio(message, true);
    }
  });

  Campfire.Responders.push("HTML5Audio");
  window.chat.installPropaneResponder("HTML5Audio", "html5audio");
}

if (true) {
  Campfire.CommitExpander = Class.create({
    initialize: function(chat) {
      this.chat = chat;
      var messages = this.chat.transcript.messages;
      for (var i = 0; i < messages.length; i++) {
        this.detectCommit(messages[i]);
      }
    },

    detectCommit: function(message) {
      if (!message.pending() && message.kind === 'text') {
        var body = message.bodyElement()
        if (body.innerText.match(/is deploying/)) {
          var m = body.innerText.match(/^(.*?)(, logs| \(http:)/i)
          var links = body.select('a')
          if (links.length && m) {
            var last_link = links[links.length-1]
            var message = (links.length == 2) ? m[1].replace(/\((.*?)\)/, function(all,match){ return "(<a target='_blank' href='"+links[0].href+"'>" + match + "</a>)" }) : m[1]

            if (last_link.href.match(/heaven/)) {
              var build_num = last_link.href.match(/(\d+)$/)[1]
              message += ' [<b><a target="_blank" href="' + last_link.href + '">#' + build_num + '</a></b>]'
            }

            body.innerHTML = message
          }
        }
      }
    },

    onMessagesInsertedBeforeDisplay: function(messages) {
      for (var i = 0; i < messages.length; i++) {
        this.detectCommit(messages[i]);
      }
    }
  });

  Campfire.Responders.push("CommitExpander");
  window.chat.installPropaneResponder("CommitExpander", "commitexpander");
}

if (true) {
  Campfire.BuildExpander = Class.create({
    initialize: function(chat) {
      this.chat = chat;
      var messages = this.chat.transcript.messages;
      for (var i = 0; i < messages.length; i++) {
        this.detectBuild(messages[i]);
      }
    },

    detectBuild: function(message) {
      if (!message.pending() && message.kind === 'text') {
        var body = message.bodyElement()
        if (body.innerText.match(/^Build #(\d+) \([0-9a-zA-Z]+\) of (github-)?([-_0-9a-zA-Z]+)/)) {
          var failed_p = body.innerText.match(/failed/);
          var success_p = body.innerText.match(/success/);
          if (failed_p || success_p)
          var sha = body.innerText.match(/\(([0-9a-z]+)\)/i)[1]
          var build;
          if (body.outerHTML.match(/^github-(?!services)/)) {
           build = body.outerHTML.replace(/#(\d+) \(([0-9a-zA-Z]+)\) of (?:github-)?([-_0-9a-zA-Z]+)/, '<a target="_blank" href="http://ci2.rs.github.com:8080/job/github-$3/$1/console">#$1</a> ($2) of github-$3')
          } else {
            build = body.outerHTML.replace(/#(\d+) \(([0-9a-zA-Z]+)\) of ([-_0-9a-zA-Z]+)/, '<a target="_blank" href="https://janky.rs.github.com/$1/output">#$1</a> ($2) of $3')
          }
          var btime = build.match(/\d+s/)
          body.replace(build)
          build = build.replace(/^.*?<a/,'<a').replace(/<\/a>.*/, '</a>')

          var msgIndex = this.chat.transcript.messages.indexOf(message);
          if (msgIndex > -1) {
            for (var i=msgIndex; i > 0 && i > msgIndex - 5; i--) {
              var otherMsg = this.chat.transcript.messages[i]
              if (otherMsg.element.innerHTML.match("/commit/" + sha)) {
                build = build.replace(/<\/a>.*$/, '</a>').replace('Build ','');
                if (btime) build += "] [" + btime;
                otherMsg.bodyElement().insert({bottom: " ["+build+"]"})
                message.element.remove()
                break
              }
            }
          }
        }
      }
    },

    onMessagesInsertedBeforeDisplay: function(messages) {
      for (var i = 0; i < messages.length; i++) {
        this.detectBuild(messages[i]);
      }
    }
  });

  Campfire.Responders.push("BuildExpander");
  window.chat.installPropaneResponder("BuildExpander", "buildexpander");
}

if (true) {
  Campfire.DiffExpander = Class.create({
    initialize: function(chat) {
      this.chat = chat;
      var messages = this.chat.transcript.messages;
      for (var i = 0; i < messages.length; i++) {
        this.detectDiff(messages[i]);
      }
      this.chat.windowmanager.scrollToBottom();
    },

    detectDiff: function(message) {
      if (message.kind === 'paste') {
        var code = message.bodyCell.select('pre code')
        if (code.length) {
          var diff = code[0].innerText
          if (diff.match(/^\+\+\+/m)) {
            var lines = diff.split("\n").map(function(line){
              if (line.match(/^(diff|index)/)) {
                return "<b>"+line.escapeHTML()+"</b>"
              } else if (match = line.match(/^(@@.+?@@)(.*)$/)) {
                return "<b>"+match[1]+"</b> " + match[2].escapeHTML()
              } else if (line.match(/^\+/)) {
                return "<font style='color:green'>"+line.escapeHTML()+"</font>"
              } else if (line.match(/^\-/)) {
                return "<font style='color:red'>"+line.escapeHTML()+"</font>"
              } else {
                return line.escapeHTML()
              }
            })
            code[0].innerHTML = lines.join("\n")
          }
        }
      }
    },

    onMessagesInsertedBeforeDisplay: function(messages) {
      var scrolledToBottom = this.chat.windowmanager.isScrolledToBottom();
      for (var i = 0; i < messages.length; i++) {
        this.detectDiff(messages[i]);
      }
      if (scrolledToBottom) {
        this.chat.windowmanager.scrollToBottom();
      }
    },

    onMessageAccepted: function(message, messageID) {
      this.detectDiff(message);
    }
  });

  Campfire.Responders.push("DiffExpander");
  window.chat.installPropaneResponder("DiffExpander", "diffexpander");
}

if (true) {
  Campfire.StacheExpander = Class.create({
    initialize: function(chat) {
      this.chat = chat;
      var messages = this.chat.transcript.messages;
      for (var i = 0; i < messages.length; i++) {
        this.detectStache(messages[i]);
      }
    },

    detectStache: function(message) {
      if (!message.pending() && message.kind === 'text') {
        var body = message.bodyElement()
        var imgs = body.select('a.image[href*="mustachify.me"]')
        if (imgs.length) {
          var src = decodeURIComponent(imgs[0].href.replace(/^.*\?src=/,''))

          var msgIndex = this.chat.transcript.messages.indexOf(message);
          if (msgIndex > -1) {
            for (var i=msgIndex-1; i > 0 && i > msgIndex - 7; i--) {
              var otherMsg = this.chat.transcript.messages[i]
              var found = otherMsg.bodyElement().select('a.image')
              if (found.length) {
                var h = found[0].href.replace(/#\....$/,'')
                if (h == src || decodeURIComponent(h) == src) {
                  otherMsg.bodyElement().select('a.image')[0].setStyle({'padding-right': '5px'})
                  otherMsg.bodyElement().insert({bottom: imgs[0]})
                  message.element.remove()
                  break
                }
              }
            }
          }

        }
      }
    },

    onMessagesInsertedBeforeDisplay: function(messages) {
      for (var i = 0; i < messages.length; i++) {
        this.detectStache(messages[i]);
      }
    }
  });

  Campfire.Responders.push("StacheExpander");
  window.chat.installPropaneResponder("StacheExpander", "stacheexpander");
}

if (true) {
  Campfire.MusicExpander = Class.create({
    initialize: function(chat) {
      this.chat = chat;
      var messages = this.chat.transcript.messages;
      for (var i = 0; i < messages.length; i++) {
        this.detectMusic(messages[i]);
      }
      this.chat.windowmanager.scrollToBottom();
    },

    detectMusic: function(message) {
      if (message.actsLikeTextMessage()) {
        var body = message.bodyElement()
        var html = body.innerHTML

        var match = html.match(/(Now playing|is listening to|Queued up) "(.*)" by (.*), from(?: the album)? "(.*)"(.*)/i)
        if (match) {
          var text = match[1]
          var song = match[2], artist = match[3], album = match[4], rest = match[5]
          var url = "http://www.amazon.com/s/ref=nb_sb_noss?url=search-alias%3Ddigital-music&x=8&y=16&field-keywords="
          var linkify = function(text, query){
            if (!query) query = text
            return new Element('a', {target:'_blank',href:url+encodeURI(query)}).update(text).outerHTML;
          }

          html = text + ' "'
          if (song)
            html += linkify(song, song+" "+artist+" "+album)
          html += '" by '
          if (artist)
            html += linkify(artist)
          html += ', from the album "'
          if (album)
            html += linkify(album, artist+" "+album)
          html += '"'
          html += rest
          body.innerHTML = html
        }
      }
    },

    onMessagesInsertedBeforeDisplay: function(messages) {
      var scrolledToBottom = this.chat.windowmanager.isScrolledToBottom();
      for (var i = 0; i < messages.length; i++) {
        this.detectMusic(messages[i]);
      }
      if (scrolledToBottom) {
        this.chat.windowmanager.scrollToBottom();
      }
    },

    onMessageAccepted: function(message, messageID) {
      this.detectMusic(message);
    }
  });

  Campfire.Responders.push("MusicExpander");
  window.chat.installPropaneResponder("MusicExpander", "musicexpander");
}

window.chat.messageHistory = 800;