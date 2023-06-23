; ACT-R model for analyzing try-except python code
;
; This code implements an ACT-R method for analyzing and scoring the
; effectiveness of its defensive try-except coding practices
;
; This file complements the paper "Bridging the Cognition Gap: An ACT-R Model for Analyzing and Improving Defensive Techniques in AI-Generated Code"
; Copyright Tate DeTerra
; 6/23/23

(clear-all)

(define-model analyze

(sgp :v t :show-focus t :trace-detail low :esc t)

(chunk-type scan-code step index xpos ypos curr last last2 type errs str filename blocking)
(chunk-type scan-dangers step ypos xpos ytry funcflag)
(chunk-type scan-excepts step ypos xpos mode ex yexcept)
(chunk-type scan-handle step err yexcept orig filename cht)

(chunk-type trigger curr prev pprev act type errors str)
(chunk-type open mode cur prev pprev errors)
(chunk-type socket block errors)

(chunk-type hierarchy exception partof)

(chunk-type func ydef yfunc name1 name2)
(chunk-type except yline line)
(chunk-type scope ytry yexcept)
(chunk-type handle string yexcept line)
(chunk-type extrahandle string file line)

(add-dm
; Step chunks
(done isa chunk)
(start isa chunk)
(attend isa chunk)
(compare isa chunk)
(recognize isa chunk)

(find-file isa chunk)
(attend-file isa chunk)
(note-file isa chunk)

(attend-mode isa chunk)
(find-mode isa chunk)
(validate-mode isa chunk)

(get-func isa chunk)
(get-func2 isa chunk)
(attend-func isa chunk)
(note-func-trigger isa chunk)

(log-func isa chunk)
(log-except isa chunk)
(report-errors isa chunk)

(find-socket isa chunk)
(report-socket isa chunk)

(find-blocking isa chunk)
(attend-blocking isa chunk)
(note-blocking isa chunk)

(start-scope isa chunk)
(find-try isa chunk)
(attend-try isa chunk)
(validate-try isa chunk)
(find-scope isa chunk)

(goto-func isa chunk)

(attend-except isa chunk)
(validate-except isa chunk)

(start-except isa chunk)
(attend-exc isa chunk)
(validate-exc isa chunk)

(attend-exception isa chunk)
(review-exception isa chunk)
(get-exceptline isa chunk)

(group isa chunk)
(attend-socket-dot isa chunk)
(attend-socket-except isa chunk)
(report-socket-except isa chunk)

(get-handle isa chunk)
(validate-handle isa chunk)
(get-group isa chunk)

(check-extra isa chunk)
(validate-extra isa chunk)

; Trigger chunks
(t01 isa trigger curr "open" prev "with" act find-file type 0 errors ("NULL") str "open file")
(t02 isa trigger curr "open" prev "." pprev "os" act find-file type 0 errors ("NULL") str "open file")
(t03 isa trigger curr "open" prev "=" act find-file type 0 errors ("NULL") str "open file")
(t04 isa trigger curr "(" prev "open" act find-file type 0 errors ("NULL") str "open file")
(t05 isa trigger curr "('" prev "open" act find-file type 0 errors ("NULL") str "open file")
(t1 isa trigger curr "rename" prev "." pprev "os" act find-file type 0 errors (("FileNotFoundError" nil) ("PermissionError" nil)) str "rename file")
(t2 isa trigger curr "remove" prev "." pprev "os" act find-file type 0 errors (("FileNotFoundError" nil) ("PermissionError" nil) ("IsADirectoryError" nil)) str "delete file")
(t3 isa trigger curr "mkdir" prev "." pprev "os" act find-file type 0 errors (("FileNotFoundError" nil) ("PermissionError" nil) ("FileExistsError" nil)) str "create directory")
(t4 isa trigger curr "makedirs" prev "." pprev "os" act find-file type 0 errors (("FileNotFoundError" nil) ("PermissionError" nil) ("FileExistsError" nil)) str "create directories")
(t5 isa trigger curr "rmdir" prev "." pprev "os" act find-file type 0 errors (("FileNotFoundError" nil) ("PermissionError" nil) ("NotADirectoryError" nil)) str "remove directory")
(t6 isa trigger curr "'" prev "b" act report-errors type 1 errors (("UnicodeEncodeError" nil)) str "unicode string")
(t71 isa trigger curr "encode" prev "." act report-errors type 1 errors (("UnicodeEncodeError" nil)) str "unicode encode")
(t72 isa trigger curr "encode" prev ")." act report-errors type 1 errors (("UnicodeEncodeError" nil)) str "unicode encode")
(t73 isa trigger curr "encode" prev "'." act report-errors type 1 errors (("UnicodeEncodeError" nil)) str "unicode encode")
(t74 isa trigger curr "encode" prev "}'." act report-errors type 1 errors (("UnicodeEncodeError" nil)) str "unicode encode")
(t81 isa trigger curr "decode" prev "." act report-errors type 1 errors (("UnicodeDecodeError" nil)) str "unicode decode")
(t82 isa trigger curr "decode" prev ")." act report-errors type 1 errors (("UnicodeDecodeError" nil)) str "unicode decode")
(t9 isa trigger curr "recv" prev "." act find-socket type 2 errors ("NULL") str "socket receive")
(t10 isa trigger curr "recvfrom" prev "." act find-socket type 2 errors ("NULL") str "socket receive")
(t11 isa trigger curr "send" prev "." act find-socket type 2 errors ("NULL") str "socket send")
(t12 isa trigger curr "sendto" prev "." act find-socket type 2 errors ("NULL") str "socket send")
(t13 isa trigger curr "sendall" prev "." act find-socket type 2 errors ("NULL") str "socket send")

(t20 isa trigger curr "def" prev "" act get-func type 0 errors ("NULL") str "NULL")
(t21 isa trigger curr "except" prev "" act log-except type 0 errors ("NULL") str "NULL")
(t22 isa trigger curr "setblocking" prev "." act find-blocking type 0 errors ("NULL") str "NULL")
(t23 isa trigger curr "exists" prev "." pprev "path" act find-file type 0 errors "exists" str "logextra")
(t24 isa trigger curr "isfile" prev "." pprev "path" act find-file type 0 errors "isfile" str "logextra")
(t25 isa trigger curr "isdir" prev "." pprev "path" act find-file type 0 errors "isdir" str "logextra")
(t26 isa trigger curr "access" prev "." pprev "os" act find-file type 0 errors "access" str "logextra")

(o0 isa open mode "r" cur "')" prev "r" pprev "'" errors (("FileNotFoundError" nil) ("PermissionError" nil) ("IsADirectoryError" nil)))
(o1 isa open mode "r" cur "'," prev "r" pprev "'" errors (("FileNotFoundError" nil) ("PermissionError" nil) ("IsADirectoryError" nil)))
(o2 isa open mode "w" cur "')" prev "w" pprev "'" errors (("FileNotFoundError" nil) ("PermissionError" nil) ("IsADirectoryError" nil)))
(o3 isa open mode "w" cur "'," prev "w" pprev "'" errors (("FileNotFoundError" nil) ("PermissionError" nil) ("IsADirectoryError" nil)))
(o4 isa open mode "x" cur "')" prev "x" pprev "'" errors (("FileExistsError" nil) ("PermissionError" nil) ("IsADirectoryError" nil)))
(o5 isa open mode "x" cur "'," prev "x" pprev "'" errors (("FileExistsError" nil) ("PermissionError" nil) ("IsADirectoryError" nil)))
(o6 isa open mode "a" cur "')" prev "a" pprev "'" errors (("FileNotFoundError" nil) ("PermissionError" nil) ("IsADirectoryError" nil)))
(o7 isa open mode "a" cur "'," prev "a" pprev "'" errors (("FileNotFoundError" nil) ("PermissionError" nil) ("IsADirectoryError" nil)))
(o8 isa open mode "b" cur "')" prev "b" pprev "'" errors (("FileNotFoundError" nil) ("PermissionError" nil) ("IsADirectoryError" nil)))
(o9 isa open mode "b" cur "'," prev "b" pprev "'" errors (("FileNotFoundError" nil) ("PermissionError" nil) ("IsADirectoryError" nil)))
(o10 isa open mode "t" cur "')" prev "t" pprev "'" errors (("FileNotFoundError" nil) ("PermissionError" nil) ("IsADirectoryError" nil)))
(o11 isa open mode "t" cur "'," prev "t" pprev "'" errors (("FileNotFoundError" nil) ("PermissionError" nil) ("IsADirectoryError" nil)))
(o12 isa open mode "+" cur "'+')" errors (("FileNotFoundError" nil) ("PermissionError" nil) ("IsADirectoryError" nil)))
(o13 isa open mode "+" cur "'+'," errors (("FileNotFoundError" nil) ("PermissionError" nil) ("IsADirectoryError" nil)))
(o14 isa open mode "r+" cur "+')" prev "r" errors (("FileNotFoundError" nil) ("PermissionError" nil) ("IsADirectoryError" nil)))
(o15 isa open mode "r+" cur "+'," prev "r" errors (("FileNotFoundError" nil) ("PermissionError" nil) ("IsADirectoryError" nil)))
(o16 isa open mode "w+" cur "+')" prev "w" errors (("PermissionError" nil) ("IsADirectoryError" nil)))
(o17 isa open mode "w+" cur "+'," prev "w" errors (("PermissionError" nil) ("IsADirectoryError" nil)))
(o18 isa open mode "a+" cur "+')" prev "a" errors (("PermissionError" nil) ("IsADirectoryError" nil)))
(o19 isa open mode "a+" cur "+'," prev "a" errors (("PermissionError" nil) ("IsADirectoryError" nil)))
(o20 isa open mode "rb" cur "')" prev "rb" pprev "'" errors (("FileNotFoundError" nil) ("PermissionError" nil) ("IsADirectoryError" nil)))
(o21 isa open mode "rb" cur "'," prev "rb" pprev "'" errors (("FileNotFoundError" nil) ("PermissionError" nil) ("IsADirectoryError" nil)))
(o22 isa open mode "wb" cur "')" prev "wb" pprev "'" errors (("FileNotFoundError" nil) ("PermissionError" nil) ("IsADirectoryError" nil)))
(o23 isa open mode "wb" cur "'," prev "wb" pprev "'" errors (("FileNotFoundError" nil) ("PermissionError" nil) ("IsADirectoryError" nil)))
(o24 isa open mode "xb" cur "')" prev "xb" pprev "'" errors (("FileExistsError" nil) ("PermissionError" nil) ("IsADirectoryError" nil)))
(o25 isa open mode "xb" cur "'," prev "xb" pprev "'" errors (("FileExistsError" nil) ("PermissionError" nil) ("IsADirectoryError" nil)))
(o26 isa open mode "ab" cur "')" prev "ab" pprev "'" errors (("FileNotFoundError" nil) ("PermissionError" nil) ("IsADirectoryError" nil)))
(o27 isa open mode "ab" cur "'," prev "ab" pprev "'" errors (("FileNotFoundError" nil) ("PermissionError" nil) ("IsADirectoryError" nil)))
(o28 isa open mode "rb+" cur "+')" prev "rb" errors (("FileNotFoundError" nil) ("PermissionError" nil) ("IsADirectoryError" nil)))
(o29 isa open mode "rb+" cur "+'," prev "rb" errors (("FileNotFoundError" nil) ("PermissionError" nil) ("IsADirectoryError" nil)))
(o30 isa open mode "r+b" cur "b" prev "+" pprev "r" errors (("FileNotFoundError" nil) ("PermissionError" nil) ("IsADirectoryError" nil)))
(o31 isa open mode "wb+" cur "+')" prev "wb" errors (("PermissionError" nil) ("IsADirectoryError" nil)))
(o32 isa open mode "wb+" cur "+'," prev "wb" errors (("PermissionError" nil) ("IsADirectoryError" nil)))
(o33 isa open mode "w+b" cur "b" prev "+" pprev "w" errors (("PermissionError" nil) ("IsADirectoryError" nil)))
(o34 isa open mode "ab+" cur "+')" prev "ab" errors (("PermissionError" nil) ("IsADirectoryError" nil)))
(o35 isa open mode "ab+" cur "+'," prev "ab" errors (("PermissionError" nil) ("IsADirectoryError" nil)))
(o36 isa open mode "a+b" cur "b" prev "+" pprev "a" errors (("PermissionError" nil) ("IsADirectoryError" nil)))

(s0 isa socket block "True" errors (("BrokenPipeError" nil) ("ConnectionAbortedError" nil) ("ConnectionResetError" nil) ("TimeoutError" nil)))
(s1 isa socket block "False" errors (("BrokenPipeError" nil) ("ConnectionAbortedError" nil) ("ConnectionResetError" nil) ("TimeoutError" nil) ("BlockingIOError" nil)))

; Exception chunks
(e01 isa hierarchy exception "FileNotFoundError" partof "OSError")
(e02 isa hierarchy exception "FileExistsError" partof "OSError")
(e03 isa hierarchy exception "PermissionError" partof "OSError")
(e04 isa hierarchy exception "IsADirectoryError" partof "OSError")
(e05 isa hierarchy exception "NotADirectoryError" partof "OSError")

(e11 isa hierarchy exception "ConnectionError" partof "socket.error")
(e12 isa hierarchy exception "BlockingIOError" partof "socket.error")
(e13 isa hierarchy exception "BrokenPipeError" partof "ConnectionError")
(e14 isa hierarchy exception "ConnectionResetError" partof "ConnectionError")
(e15 isa hierarchy exception "ConnectionAbortedError" partof "ConnectionError")
(e16 isa hierarchy exception "TimeoutError" partof "socket.timeout")

(e21 isa hierarchy exception "socket.gaierror" partof "socket.herror")
(e22 isa hierarchy exception "socket.herror" partof "socket.error")
(e23 isa hierarchy exception "socket.timeout" partof "socket.error")
(e24 isa hierarchy exception "socket.error" partof "OSError")

(e31 isa hierarchy exception "UnicodeEncodeError" partof "UnicodeError")
(e32 isa hierarchy exception "UnicodeDecodeError" partof "UnicodeError")
(e33 isa hierarchy exception "UnicodeError" partof "ValueError")

(e41 isa hierarchy exception "OSError" partof "IOError")

; Goal chunks
(goal1 isa scan-code step done blocking "True")
(goal2 isa scan-dangers step done)
(goal3 isa scan-excepts step done)
(goal4 isa scan-handle step done)
)

; Productions to find error-prone code, ensure encapsulation, and identify encapsulation
(P start-danger
    =goal>
        isa scan-code
        step start
        ypos nil
    ==>
    +visual-location>
        ISA visual-location
        screen-y lowest
        screen-x lowest
    =goal>
        step attend
)

(P continue-danger-next
    =goal>
        isa scan-code
        step start
        ypos =y
        xpos nil
    ==>
    +visual-location>
        ISA visual-location
        > screen-y =y
        screen-y lowest
        screen-x lowest
    =goal>
        step attend
)

(P continue-danger
    =goal>
        isa scan-code
        step start
        ypos =y
        xpos =x
    ==>
    +visual-location>
        ISA visual-location
        screen-y =y
        > screen-x =x
        screen-x lowest
    =goal>
        step attend
)

(P attend-code
    =goal>
        isa scan-code
        step attend
    =visual-location>
        screen-y =y
        screen-x =x
    ?visual>
        state free
    ==>
    +visual>
        cmd move-attention
        screen-pos =visual-location
    =goal>
        step compare
        ypos =y
        xpos =x
)

(P compare-code
    =goal>
        isa scan-code
        step compare
        curr =c
        last =l
    =visual>
        isa visual-object
        value =v
    ==>
    +retrieval>
        isa trigger
        curr =v
        prev =c
    =goal>
        step recognize
        curr =v
        last =c
        last2 =l
)

(P compare-comment
    =goal>
        isa scan-code
        step compare
    =visual>
        isa visual-object
        value "#"
    ==>
    =goal>
        step done
        xpos nil
)

(P compare-print
    =goal>
        isa scan-code
        step compare
        last ""
    =visual>
        isa visual-object
        value "print"
    ==>
    =goal>
        step done
        xpos nil
)

;next code
(P not-danger
    =goal>
        isa scan-code
        step recognize
    ?retrieval>
        buffer failure
    ==>
    +visual-location>
        ISA visual-location
        :attended nil
        :nearest current-x
        > screen-x current
        screen-y current
    =goal>
        step attend
)

;found trigger
(P recognize-trigger-prev
    =goal>
        isa scan-code
        step recognize
        last =p
    =retrieval>
        isa trigger
        type =t
        act =a
        errors =e
        str =s
        prev =p
    ==>
    +visual-location>
        ISA visual-location
        :attended nil
        :nearest current-x
        > screen-x current
        screen-y current
    =goal>
        step =a
        errs =e
        type =t
        str =s
)

(P recognize-trigger-pprev
    =goal>
        isa scan-code
        step recognize
        last =p
        last2 =p2
    =retrieval>
        isa trigger
        type =t
        act =a
        errors =e
        str =s
        prev =p
        pprev =p2
    ==>
    +visual-location>
        ISA visual-location
        :attended nil
        :nearest current-x
        > screen-x current
        screen-y current
    =goal>
        step =a
        errs =e
        type =t
        str =s
)

;end of line
(P no-danger
    =goal>
        isa scan-code
        step attend
    ?visual-location>
        buffer failure
    ==>
    =goal>
        step done
        xpos nil
)

;report danger
(P basic-danger
    =goal>
        isa scan-code
        step report-errors
        ypos =y
        index =i
        errs =e
        type =t
        str =s
    ==>
    !bind! =out (setf *response* (list (list =t =s) =y =i =e))
    =goal>
        step done
)

;find filename
(P find-file
    =goal>
        isa scan-code
        step find-file
    =visual-location>
    ?visual>
        state free
    ==>
    +visual>
        cmd move-attention
        screen-pos =visual-location
    +visual-location>
        ISA visual-location
        :attended nil
        :nearest current-x
        > screen-x current
        screen-y current
    =goal>
        step attend-file
)

(P attend-file
    =goal>
        isa scan-code
        step attend-file
    =visual-location>
    ?visual>
        state free
    ==>
    +visual>
        cmd move-attention
        screen-pos =visual-location
    =goal>
        step note-file
)

(P return-danger
    =goal>
        isa scan-code
        step note-file
        ypos =y
        index =i
        type =t
        errs =e
        str =s
    =visual>
        isa visual-object
        value =f
    ==>
    !bind! =out (setf *response* (list (list =t =s =f) =y =i =e))
    =goal>
        step done
)

(P note-file
    =goal>
        isa scan-code
        step note-file
        str "open file"
    =visual>
        isa visual-object
        value =f
    ==>
    +visual-location>
        ISA visual-location
        :attended nil
        :nearest current-x
        > screen-x current
        screen-y current
    =goal>
        step attend-mode
        filename =f
)

;find function name
(P attend-func1
    =goal>
        isa scan-code
        step get-func
    =visual-location>
    ?visual>
        state free
    ==>
    +visual>
        cmd move-attention
        screen-pos =visual-location
    =goal>
        step get-func2
)

(P get-func2
    =goal>
        isa scan-code
        step get-func2
    =visual>
        isa visual-object
        value =f
    ==>
    +visual-location>
        ISA visual-location
        :attended nil
        :nearest current-x
        > screen-x current
        screen-y current
    =goal>
        curr =f
        step attend-func
)

(P attend-func2
    =goal>
        isa scan-code
        step attend-func
    =visual-location>
    ?visual>
        state free
    ==>
    +visual>
        cmd move-attention
        screen-pos =visual-location
    =goal>
        step note-func-trigger
)

(P note-func-trigger
    =goal>
        isa scan-code
        step note-func-trigger
        curr =c
        ypos =y
    =visual>
        isa visual-object
        value =f
    ?imaginal>
        state free
    ==>
    +imaginal>
        isa trigger
        curr =f
        prev =c
        act log-func
        type =y
        errors ("NULL")
        str "NULL"
    =goal>
        step done
        xpos nil
)

;note function definition
(P note-func
    =goal>
        isa scan-code
        step log-func
        ypos =y2
        curr =c
        last =p
        type =y1
    ?imaginal>
        state free
    ==>
    +imaginal>
        isa func
        ydef =y1
        yfunc =y2
        name1 =c
        name2 =p
    =goal>
        step done
        xpos nil
)

;note additional checks
(P note-extrahandle
    =goal>
        isa scan-code
        step note-file
        str "logextra"
        errs =s
        index =i
    =visual>
        isa visual-object
        value =f
    ?imaginal>
        state free
    ==>
    +imaginal>
        isa extrahandle
        string =s
        file =f
        line =i
    +visual-location>
        ISA visual-location
        :attended nil
        :nearest current-x
        > screen-x current
        screen-y current
    =goal>
        step attend
)

;find open mode
(P no-mode
    =goal>
        isa scan-code
        step attend-mode
    ?visual-location>
        buffer failure
    ==>
    +retrieval>
        isa open
        cur "')"
        prev "r"
        pprev "'"
    =goal>
        step validate-mode
)

(P attend-mode
    =goal>
        isa scan-code
        step attend-mode
    =visual-location>
    ?visual>
        state free
    ==>
    +visual>
        cmd move-attention
        screen-pos =visual-location
    =goal>
        step find-mode
        errs 0
)

(P find-mode-1
    =goal>
        isa scan-code
        step find-mode
        errs 0
        curr =c
        last =l
    =visual>
        isa visual-object
        value =m
    ==>
    +retrieval>
        isa open
        cur =m
        prev =c
        pprev =l
    =goal>
        step validate-mode
        errs 1
        curr =m
        last =c
        last2 =l
)

(P find-mode-2
    =goal>
        isa scan-code
        step find-mode
        errs 1
        curr =c
        last =l
    ==>
    +retrieval>
        isa open
        cur =c
        prev =l
        pprev nil
    =goal>
        step validate-mode
        errs 2
)

(P find-mode-3
    =goal>
        isa scan-code
        step find-mode
        errs 2
        curr =c
    ==>
    +retrieval>
        isa open
        cur =c
        prev nil
        pprev nil
    =goal>
        step validate-mode
        errs 3
)

(P next-mode
    =goal>
        isa scan-code
        step validate-mode
    ?retrieval>
        buffer failure
    ==>
    =goal>
        step find-mode
)

(P not-mode
    =goal>
        isa scan-code
        step validate-mode
        errs 3
    ?retrieval>
        buffer failure
    ==>
    +visual-location>
        ISA visual-location
        :attended nil
        :nearest current-x
        > screen-x current
        screen-y current
    =goal>
        step attend-mode
)

(P recognize-mode
    =goal>
        isa scan-code
        step validate-mode
        ypos =y
        type =t
        index =i
        filename =f
        str =s
    =retrieval>
        isa open
        errors =e
        mode =m
    ==>
    !bind! =out (setf *response* (list (list =t =s =f =m) =y =i =e))
    =goal>
        step done
)

;find socket blocking mode
(P find-blocking
    =goal>
        isa scan-code
        step find-blocking
    =visual-location>
    ?visual>
        state free
    ==>
    +visual>
        cmd move-attention
        screen-pos =visual-location
    +visual-location>
        ISA visual-location
        :attended nil
        :nearest current-x
        > screen-x current
        screen-y current
    =goal>
        step attend-blocking
)

(P attend-blocking
    =goal>
        isa scan-code
        step attend-blocking
    =visual-location>
    ?visual>
        state free
    ==>
    +visual>
        cmd move-attention
        screen-pos =visual-location
    =goal>
        step note-blocking
)

(P note-blocking-false
    =goal>
        isa scan-code
        step note-blocking
    =visual>
        isa visual-object
        value "False"
        value =v
    ==>
    =goal>
        step done
        blocking =v
)

;report socket danger
(P get-socket
    =goal>
        isa scan-code
        step find-socket
        blocking =b
    ==>
    +retrieval>
        isa socket
        block =b
    =goal>
        step report-socket
)

(P report-socket
    =goal>
        isa scan-code
        step report-socket
        ypos =y
        type =t
        index =i
        blocking =b
        str =s
    =retrieval>
        isa socket
        errors =e
    ==>
    !bind! =out (setf *response* (list (list =t =s =b) =y =i =e))
    =goal>
        step done
)

(P log-except
    =goal>
        isa scan-code
        step log-except
        ypos =y
        index =i
    ?imaginal>
        state free
    ==>
    +imaginal>
        isa except
        yline =y
        line =i
    =goal>
        step done
        xpos nil
)

; Productions to validate danger encapsulation
(P search-try
    =goal>
        isa scan-dangers
        step start-scope
        ypos =y
    ==>
    +visual-location>
        ISA visual-location
        screen-y =y
        screen-x lowest
    =goal>
        step attend-try
)

(P attend-try
    =goal>
        isa scan-dangers
        step attend-try
    =visual-location>
        screen-y =y
    ?visual>
        state free
    ==>
    +visual>
        cmd move-attention
        screen-pos =visual-location
    =goal>
        step validate-try
        ytry =y
)

(P attend-try-first
    =goal>
        isa scan-dangers
        step attend-try
        xpos nil
    =visual-location>
        screen-x =x
    ?visual>
        state free
    ==>
    +visual>
        cmd move-attention
        screen-pos =visual-location
    =goal>
        step validate-try
        xpos =x
)

(P no-try
    =goal>
        isa scan-dangers
        step attend-try
    ?visual-location>
        buffer failure
    ==>
    =goal>
        step done
)

(P not-try
    =goal>
        isa scan-dangers
        step validate-try
        xpos =x
    =visual>
        isa visual-object
        - value "try"
    ==>
    !bind! =x0 (- =x 20)
    +visual-location>
        ISA visual-location
        < screen-y current
        < screen-x =x0
        screen-y highest
        screen-x lowest
    =goal>
        step attend-try
)

(P bad-try
    =goal>
        isa scan-dangers
        step validate-try
    =visual>
        isa visual-object
        value "except"
    ==>
    =goal>
        step done
)

(P is-func-bad
    =goal>
        isa scan-dangers
        step validate-try
        ytry =y
        funcflag t
    =visual>
        isa visual-object
        value "def"
    ==>
    =goal>
        step done
)

(P is-func
    =goal>
        isa scan-dangers
        step validate-try
        ytry =y
        funcflag nil
    =visual>
        isa visual-object
        value "def"
    ==>
    +retrieval>
        isa func
        ydef =y
    =goal>
        step goto-func
        funcflag t
)

(P is-try
    =goal>
        isa scan-dangers
        step validate-try
        ytry =y
    =visual>
        isa visual-object
        value "try"
    ==>
    +retrieval>
        isa scope
        ytry =y
    =goal>
        step find-scope
)

(P no-scope
    =goal>
        isa scan-dangers
        step find-scope
        ypos =y
        xpos =x
    ?retrieval>
        buffer failure
    ==>
    !bind! =x0 (- =x 12)
    +visual-location>
        ISA visual-location
        > screen-y =y
        < screen-x =x0
        screen-y lowest
        screen-x lowest
    =goal>
        step attend-except
)

(P report-scope
    =goal>
        isa scan-dangers
        step find-scope
    =retrieval>
        isa scope
        ytry =yt
        yexcept =ye
    ==>
    !bind! =out (setf *response* (list 0 (list =yt =ye)))
    =goal>
        step done
)

(P continue-func
    =goal>
        isa scan-dangers
        step goto-func
    =retrieval>
        isa func
        yfunc =y
    ==>
    +visual-location>
        ISA visual-location
        screen-y =y
        screen-x lowest
    =goal>
        step attend-try
        ypos =y
        xpos nil
)

(P no-func
    =goal>
        isa scan-dangers
        step goto-func
    ?retrieval>
        buffer failure
    ==>
    =goal>
        step done
)

(P attend-except
    =goal>
        isa scan-dangers
        step attend-except
    =visual-location>
        screen-y =y
    ?visual>
        state free
    ==>
    +visual>
        cmd move-attention
        screen-pos =visual-location
    =goal>
        step validate-except
        ypos =y
)

(P no-except
    =goal>
        isa scan-dangers
        step attend-except
    ?visual-location>
        buffer failure
    ==>
    =goal>
        step done
)

(P not-except
    =goal>
        isa scan-dangers
        step validate-except
        xpos =x
    =visual>
        isa visual-object
        - value "except"
    ==>
    !bind! =x0 (- =x 20)
    +visual-location>
        ISA visual-location
        > screen-y current
        < screen-x =x0
        screen-y lowest
        screen-x lowest
    =goal>
        step attend-except
)

(P is-except
    =goal>
        isa scan-dangers
        step validate-except
        ytry =yt
        ypos =ye
    =visual>
        isa visual-object
        value "except"
    ?imaginal>
        state free
    ==>
    !bind! =out (setf *response* (list 1 (list =yt =ye)))
    +imaginal>
        isa scope
        ytry =yt
        yexcept =ye
    =goal>
        step done
)

; Productions to report exceptions tested
(P start-except
    =goal>
        isa scan-excepts
        step start-except
        ypos =y
        xpos nil
    ==>
    +visual-location>
        ISA visual-location
        screen-y =y
        screen-x lowest
    =goal>
        step attend-exc
        yexcept =y
)

(P next-except
    =goal>
        isa scan-excepts
        step start-except
        xpos =x
        mode nil
    ==>
    !bind! =x0 (- =x 14)
    +visual-location>
        ISA visual-location
        > screen-x =x0
        <= screen-x =x
        > screen-y current
        screen-y lowest
    =goal>
        step attend-exc
)

(P next-except-group
    =goal>
        isa scan-excepts
        step start-except
        xpos =x
        mode group
    ==>
    +visual-location>
        ISA visual-location
        :nearest current-x
        > screen-x current
        screen-y current
    =goal>
        step attend-exception
)

(P no-exc
    =goal>
        isa scan-excepts
        step attend-exc
    ?visual-location>
        buffer failure
    ==>
    =goal>
        step done
)

(P attend-exc
    =goal>
        isa scan-excepts
        step attend-exc
    =visual-location>
    screen-y =y
    ?visual>
        state free
    ==>
    +visual>
        cmd move-attention
        screen-pos =visual-location
    =goal>
        step validate-exc
        ypos =y
)

(P attend-exc-first
    =goal>
        isa scan-excepts
        step attend-exc
        xpos nil
    =visual-location>
        screen-x =x
    ?visual>
        state free
    ==>
    +visual>
        cmd move-attention
        screen-pos =visual-location
    =goal>
        step validate-exc
        xpos =x
)

(P not-exc
    =goal>
        isa scan-excepts
        step validate-exc
    =visual>
        isa visual-object
        - value "except"
    ==>
    =goal>
        step done
)

(P not-exc-comment
    =goal>
        isa scan-excepts
        step validate-exc
        xpos =x
    =visual>
        isa visual-object
        value "#"
    ==>
    !bind! =x0 (- =x 14)
    +visual-location>
        ISA visual-location
        > screen-x =x0
        <= screen-x =x
        > screen-y current
        screen-y lowest
    =goal>
        step attend-exc
)

(P validate-exc
    =goal>
        isa scan-excepts
        step validate-exc
    =visual>
        isa visual-object
        value "except"
    ==>
    +visual-location>
        ISA visual-location
        :nearest current-x
        > screen-x current
        screen-y current
    =goal>
        step attend-exception
)

(P attend-exception
    =goal>
        isa scan-excepts
        step attend-exception
    =visual-location>
    ?visual>
        state free
    ==>
    +visual>
        cmd move-attention
        screen-pos =visual-location
    =goal>
        step review-exception
)

(P review-exception
    =goal>
        isa scan-excepts
        step review-exception
        ypos =y
    =visual>
        isa visual-object
        value =e
    ==>
    +retrieval>
        isa except
        yline =y
    =goal>
        step get-exceptline
        ex =e
)

(P review-exception-group
    =goal>
        isa scan-excepts
        step review-exception
    =visual>
        isa visual-object
        value "("
    ==>
    +visual-location>
        ISA visual-location
        :nearest current-x
        > screen-x current
        screen-y current
    =goal>
        step attend-exception
        mode group
)

(P review-exception-comma
    =goal>
        isa scan-excepts
        step review-exception
        mode group
    =visual>
        isa visual-object
        value ","
    ==>
    +visual-location>
        ISA visual-location
        :nearest current-x
        > screen-x current
        screen-y current
    =goal>
        step attend-exception
)

(P review-exception-endgroup
    =goal>
        isa scan-excepts
        step review-exception
        xpos =x
    =visual>
        isa visual-object
        value ")"
    ==>
    !bind! =x0 (- =x 14)
    +visual-location>
        ISA visual-location
        > screen-x =x0
        <= screen-x =x
        > screen-y current
        screen-y lowest
    =goal>
        step attend-exc
        mode nil
)

(P review-exception-endgroupalt
    =goal>
        isa scan-excepts
        step review-exception
        xpos =x
    =visual>
        isa visual-object
        value "):"
    ==>
    +visual-location>
        ISA visual-location
        <= screen-x =x
        > screen-y current
        screen-y lowest
    =goal>
        step attend-exc
        mode nil
)

(P review-exception-socket
    =goal>
        isa scan-excepts
        step review-exception
    =visual>
        isa visual-object
        value "socket"
    ==>
    +visual-location>
        ISA visual-location
        :nearest current-x
        > screen-x current
        screen-y current
    =goal>
        step attend-socket-dot
)

(P attend-socket-dot
    =goal>
        isa scan-excepts
        step attend-socket-dot
    =visual-location>
    ?visual>
        state free
    ==>
    +visual>
        cmd move-attention
        screen-pos =visual-location
    +visual-location>
        ISA visual-location
        :nearest current-x
        > screen-x current
        screen-y current
    =goal>
        step attend-socket-except
)

(P attend-socket-except
    =goal>
        isa scan-excepts
        step attend-socket-except
    =visual-location>
    ?visual>
        state free
    ==>
    +visual>
        cmd move-attention
        screen-pos =visual-location
    =goal>
        step report-socket-except
)

(P report-socket-except
    =goal>
        isa scan-excepts
        step report-socket-except
        ypos =y
    =visual>
        isa visual-object
        value =e
    ==>
    !bind! =s (format nil "socket.~a" =e)
    +retrieval>
        isa except
        yline =y
    =goal>
        step get-exceptline
        ex =s
)

(P return-exception
    =goal>
        isa scan-excepts
        step get-exceptline
        ex =e
        yexcept =y
    =retrieval>
        isa except
        line =l
    ?imaginal>
        state free
    ==>
    +imaginal>
        isa handle
        string =e
        yexcept =y
        line =l
    !bind! =out (setf *response* (list =e =l 0 0 '()))
    =goal>
        step done
)

; Production to clear the imaginal buffer and create new learned information chunks
(P clear-new-imaginal-chunk
    ?imaginal>
        state free
        buffer full
    ==>
    -imaginal>
)

; Productions to test if exceptions are handled
(P check-handled
    =goal>
        isa scan-handle
        step get-handle
        err =e
        yexcept =y
    ==>
    +retrieval>
        isa handle
        string =e
        yexcept =y
    =goal>
        step validate-handle
)

(P not-handled
    =goal>
        isa scan-handle
        step validate-handle
        err =e
    ?retrieval>
        buffer failure
    ==>
    +retrieval>
        isa hierarchy
        exception =e
    =goal>
        step get-group
)

(P is-handled
    =goal>
        isa scan-handle
        step validate-handle
    =retrieval>
        isa handle
        line =l
    ==>
    !bind! =out (setf *response* =l)
    =goal>
        step done
)

(P not-hierarchy
    =goal>
        isa scan-handle
        step get-group
    ?retrieval>
        buffer failure
    ==>
    =goal>
        step check-extra
)

(P validate-hierarchy
    =goal>
        isa scan-handle
        step get-group
    =retrieval>
        isa hierarchy
        partof =e
    ==>
    =goal>
        step get-handle
        err =e
)

(P check-extra-handlefnf
    =goal>
        isa scan-handle
        step check-extra
        orig "FileNotFoundError"
        filename =f
    ==>
    +retrieval>
        isa extrahandle
        file =f
        string "isfile"
    =goal>
        step validate-extra
        cht "isfile"
)

(P check-extra-handlefee
    =goal>
        isa scan-handle
        step check-extra
        orig "FileExistsError"
        filename =f
    ==>
    +retrieval>
        isa extrahandle
        file =f
        string "isfile"
    =goal>
        step validate-extra
        cht "isfile"
)

(P check-extra-handleisd
    =goal>
        isa scan-handle
        step check-extra
        orig "IsADirectoryError"
        filename =f
    ==>
    +retrieval>
        isa extrahandle
        file =f
        string "isdir"
    =goal>
        step validate-extra
        cht "isdir"
)

(P check-extra-handlentd
    =goal>
        isa scan-handle
        step check-extra
        orig "NotADirectoryError"
        filename =f
    ==>
    +retrieval>
        isa extrahandle
        file =f
        string "isdir"
    =goal>
        step validate-extra
        cht "isdir"
)

(P check-extra-handlepme
    =goal>
        isa scan-handle
        step check-extra
        orig "PermissionError"
        filename =f
    ==>
    +retrieval>
        isa extrahandle
        file =f
        string "access"
    =goal>
        step validate-extra
        cht "access"
)

(P is-extra-handle
    =goal>
        isa scan-handle
        step validate-extra
    =retrieval>
        isa extrahandle
        line =l
    ==>
    !bind! =out (setf *response* =l)
    =goal>
        step done
)

(P not-extra
    =goal>
        isa scan-handle
        step validate-extra
    ?retrieval>
        buffer failure
    ==>
    =goal>
        step done
)

(P not-extra-nextdir
    =goal>
        isa scan-handle
        step validate-extra
        filename =f
        cht "isdir"
    ?retrieval>
        buffer failure
    ==>
    +retrieval>
        isa extrahandle
        file =f
        string "isfile"
    =goal>
        step validate-extra
        cht "isfile"
)

(P not-extra-nextfil
    =goal>
        isa scan-handle
        step validate-extra
        filename =f
        cht "isfile"
    ?retrieval>
        buffer failure
    ==>
    +retrieval>
        isa extrahandle
        file =f
        string "exists"
    =goal>
        step validate-extra
        cht "exists"
)
)