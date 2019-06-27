require(['gitbook'], function(gitbook, $) {
	gitbook.events.on('page.change', function() {
		jQuery(document).ready(function ($) {
			$('code').each(function (i, e) {
				var $wrap = $('<div>').addClass('highlight-wrap');
				var code = $(e).text();
				$(e).after($wrap);
				$wrap.append($('<button>').addClass('copy-btn').append('复制').on('click', function (e) {
					var ta = document.createElement('textarea');
					document.body.appendChild(ta);
					ta.style.position = 'absolute';
					ta.style.top = '0px';
					ta.style.left = '0px';
					ta.value = code;
					ta.select();
					ta.focus();
					var result = document.execCommand('copy');
					document.body.removeChild(ta);
					if(result)$(this).text('复制成功')
						else $(this).text('复制失败')
					})).on('mouseleave', function (e) {
						var $b = $(this).find('.copy-btn');
						setTimeout(function () {
						  $b.text('复制');
						}, 300)
				}).append(e);
			});
		});
    });
});