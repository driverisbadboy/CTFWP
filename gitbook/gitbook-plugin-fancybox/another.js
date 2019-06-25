require(['gitbook'], function(gitbook, $) {
	gitbook.events.on('page.change', function() {
		jQuery(document).ready(function ($) {
			var pathname = window.location.pathname;
			if(pathname.substr(0,10) != '/articals/' && pathname.substr(0,11) != '/reply.html') {
				$("div").removeClass("comment");
			}else{
				new Valine({
					av: AV,
					el: '.comment',
					emoticon_url: 'https://cloud.panjunwen.com/alu',
					emoticon_list: ["吐.png","喷血.png","狂汗.png","不说话.png","汗.png","坐等.png","献花.png","不高兴.png","中刀.png","害羞.png","皱眉.png","小眼睛.png","中指.png","尴尬.png","瞅你.png","想一想.png","中枪.png","得意.png","肿包.png","扇耳光.png","亲亲.png","惊喜.png","脸红.png","无所谓.png","便便.png","愤怒.png","蜡烛.png","献黄瓜.png","内伤.png","投降.png","观察.png","看不见.png","击掌.png","抠鼻.png","邪恶.png","看热闹.png","口水.png","抽烟.png","锁眉.png","装大款.png","吐舌.png","无奈.png","长草.png","赞一个.png","呲牙.png","无语.png","阴暗.png","不出所料.png","咽气.png","期待.png","高兴.png","吐血倒地.png","哭泣.png","欢呼.png","黑线.png","喜极而泣.png","喷水.png","深思.png","鼓掌.png","暗地观察.png"],
					app_id: 'TOSV1cUMEL7oFPyg7F1IBjcm-gzGzoHsz',
					app_key: 'jNEFaUyQjePIaKNgVqGAFupx',
					placeholder: 'ヾﾉ≧∀≦)o来啊，快活啊!'
				});
			};
			$(".gitbook-link").remove();
			var wig = $(window).width();
			if (wig<800) {
				$(".book-anchor").remove();
				$("#book-search-input").remove();
				$(".header-nav").remove();
				$(".page-inner").css({"padding":"20px 20px 20px 20px"});
			};
		});
    });
});