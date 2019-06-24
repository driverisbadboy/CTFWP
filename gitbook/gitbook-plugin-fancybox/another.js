var pathname = window.location.pathname;if(pathname.substr(0,10) != '/articals/' && pathname.substr(0,11) != '/reply.html'){$("div").removeClass("comment");}
$(".gitbook-link").remove();
var wig = $(window).width();
if (wig<800) {
	$(".book-anchor").remove();
	$("#book-search-input").remove();
	$(".header-nav").remove();
	$("#anchor-navigation-ex-navbar").css({"right":"50px"});
	$(".page-inner").css({"padding":"20px 20px 20px 20px"});
};

require(['gitbook'], function(gitbook, $) {
	gitbook.events.on('page.change', function() {
		jQuery(document).ready(function ($) {
			var pathname = window.location.pathname;if(pathname.substr(0,10) != '/articals/' && pathname.substr(0,11) != '/reply.html'){$("div").removeClass("comment");}
			$(".gitbook-link").remove();
			var wig = $(window).width();
			if (wig<800) {
				$(".book-anchor").remove();
				$("#book-search-input").remove();
				$(".header-nav").remove();
				$("#anchor-navigation-ex-navbar").css({"right":"50px"});
				$(".page-inner").css({"padding":"20px 20px 20px 20px"});
			};
		});
    });
});