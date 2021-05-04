interact('.digital-signature')
  .draggable({
    inertia: true,
    restrict: {
      restriction: "parent",
      endOnly: true,
      elementRect: { top: 0, left: 0, bottom: 1, right: 1 }
    },
    autoScroll: true,
    onmove: function (event) {
      var target = event.target,
          x = (parseFloat(target.getAttribute('data-x')) || 0) + event.dx,
          y = (parseFloat(target.getAttribute('data-y')) || 0) + event.dy;

      target.style.webkitTransform = target.style.transform = 'translate(' + x + 'px, ' + y + 'px)';
      target.style.border = '2px dashed #ddd';
      target.classList.remove('digital-signature--remove')

      target.setAttribute('data-x', x);
      target.setAttribute('data-y', y);
      px = (x / 96)*72
      //console.log('Coordinate X,Y(' + event.pageX + ', ' + event.pageY + ')')
      canva = document.getElementById('documentRender')
      h = canva.width - x 
      i = canva.height 
      // console.log(px)
      // console.log('Coordinate X,Y('+x +','+i+')')
      // document.getElementById('x').innerHTML = x
      // document.getElementById('y').innerHTML = y
      placeholder_x = document.getElementById('x-post')
      // placeholder_x.value = x
      placeholder_x.setAttribute('value',x)
      document.getElementById('y-post').value = 1122 - (y+68)

    },
    onend: function (event) {
      var target = event.target;
      target.classList.add('digital-signature--remove')
    }
  });
