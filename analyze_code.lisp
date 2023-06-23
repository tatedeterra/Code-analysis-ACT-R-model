; LISP code to initialize and manage the ACT-R model
;
; To run this model, load it into the ACT-R control panel and run the command (analyze *ID* DETAIL)
; where ID is the name of the global variable containing the code you wish to analyze
; and DETAIL is an optional parameter that when specified prints more details about the analysis
; (must include asterisks (**) in the *ID* field)
;
; This file complements the paper "Bridging the Cognition Gap: An ACT-R Model for Analyzing and Improving Defensive Techniques in AI-Generated Code"
; Copyright Tate DeTerra
; 6/23/23

; Load the ACT-R model and test code
(load-act-r-model "ACT-R:MODEL;analyze_model.lisp")
(load "ACT-R:MODEL;code_data.lisp")

(defvar *response* nil)
(defvar *dangers* '())
(defvar *exceptblocks* '())

; Define the main analyze function
(defun analyze (code &optional detail)

    (reset)
    (setf *dangers* '())
    (setf *exceptblocks* '())

    (write-line "STARTING!")

    (let ((window (open-exp-window "Code Window" 
                :visible t
                :width 700 
                :height 900))
            (satisfaction 0))
        (install-device window)
        (add-text-to-exp-window window code :x 0 :y 0)

    ; The first step is to scan the code for any error-prone function and retrieve the type of code
    (scan-code code)

    (if *dangers* (progn
        ; Next, we scan the dangers for try-except encapsulation
        (scan-dangers)

        ; Next, we scan the except blocks for exceptions tested
        (if *exceptblocks* (scan-excepts))

        ; Then, test that each potential error is handled
        (validate-handling)

        ; Calculate the final scores
        (setf satisfaction (calculate-score))
    )
    ; If no danger is found, 100% satisfied
    (setf satisfaction 100))

    ; Show detailed results if requested
    (if detail (generate-details))

    (write-line "======== ANALYSIS RESULTS ========")
    (write-line (format nil "~a% satisfied!" satisfaction))
    (if (/= satisfaction 100) (generate-suggestions))
    "Done!"
    )
)

; Function to count the number of lines in the code
(defun count-lines (str)
  (let ((count 1) (prev-char nil) (line-numbers '()))
    (dotimes (i (length str) count)
      (let ((current-char (char str i)))
        (if (char= current-char #\Newline) (progn
            (if (not (char= prev-char #\Newline)) (push count line-numbers))
            (incf count)
        ))
        (if (not (char= current-char #\Space)) (setf prev-char current-char))))
    (push count line-numbers)
    (reverse line-numbers))
)

; Function to run the model for identifying dangerous code
(defun scan-code (code)
    (goal-focus goal1)
    (loop for i in (count-lines code) do
        (loop
            (setf *response* nil)
            (mod-focus-fct `(step start index ,i curr "" last "" last2 ""))
            (run 600)

            (if *response* 
                (push *response* *dangers*)
                (return)
            )
        )
    )
    (setf *dangers* (reverse *dangers*))
)

; Function to run the model for identifying try-except encapsulation and identifying exceptions
(defun scan-dangers ()
    (goal-focus goal2)
    (loop for i from 0 and danger in *dangers* do

        (setf *response* nil)
        (mod-focus-fct `(step start-scope ypos ,(nth 1 danger) xpos nil funcflag nil))
        (run 600)

        (if *response*
            (if (eql 0 (first *response*)) (setf (nth i *dangers*) (append danger (nth 1 *response*)))
                (progn (setf (nth i *dangers*) (append danger (nth 1 *response*)))
                (push (nth 1 *response*) *exceptblocks*))
            )
            (setf (nth i *dangers*) (append danger (list nil nil)))
        )
    )
    (setf *exceptblocks* (reverse *exceptblocks*))
)

; Function to run the model for identifying exceptblock exceptions and lines
(defun scan-excepts ()
    (goal-focus goal3)
    (loop for i from 0 and block in *exceptblocks* do
        (let ((exceptions '()))
        (mod-focus-fct `(step start-except ypos ,(nth 1 block) xpos nil))
        (loop

            (setf *response* nil)
            (mod-focus-fct `(step start-except))
            (run 600)

            (if *response*
                (push *response* exceptions)
                (return)
            )
        )
        (setf (nth i *exceptblocks*) (append block (list (reverse exceptions))))
        )
    )
)

; Function to run the model for identifying if each possible error is handled
(defun validate-handling ()
    (goal-focus goal4)
    (loop for i from 0 and danger in *dangers* do
        (loop for e from 0 and error in (nth 3 danger) do

            (setf *response* nil)
            (mod-focus-fct `(step check-extra err ,(first error) orig ,(first error) cht nil))
            (if (eql 0 (first (first danger))) (mod-focus-fct `(filename ,(nth 2 (first danger)))))
            (if (nth 5 danger) (mod-focus-fct `(step get-handle yexcept ,(nth 5 danger))))
            (run 600)

            (if *response* (progn
                (setf (nth 1 (nth e (nth 3 (nth i *dangers*)))) *response*)
                (loop for b from 0 and block in *exceptblocks* do
                    (if (and (nth 5 danger) (eql (nth 1 block) (nth 5 danger)))
                    (loop for x from 0 and exception in (nth 2 block) do
                        (if (and (/= (nth 2 danger) (nth 3 (nth x (nth 2 (nth b *exceptblocks*))))) (eql *response* (nth 1 exception))) (progn
                        (setf (nth 2 (nth x (nth 2 (nth b *exceptblocks*)))) (+ 1 (nth 2 exception)))
                        (setf (nth 3 (nth x (nth 2 (nth b *exceptblocks*)))) (nth 2 danger))
                        (push (nth 2 danger) (nth 4 (nth x (nth 2 (nth b *exceptblocks*)))))
                        ))
                    ))
                ))
            )
        )
    )
)

; Function to print the details of the analysis
(defun generate-details ()
    (write-line "======== ANALYSIS DETAILS ========")
    (write-line "DANGERS FOUND:")
    (if *dangers*
    (loop for d from 1 and danger in *dangers* do
        (write-line (format nil "DANGER ~a" d))
        (write-line (nth 1 (first danger)))
        (write-line (format nil "   Line: ~a" (nth 2 danger)))
        (if (eql 0 (first (first danger))) (progn
            (if (string= "Open file" (nth 1 (first danger))) (write-line (format nil "   Mode: ~a" (nth 3 (first danger)))))
            (write-line (format nil "   File: ~a" (nth 2 (first danger))))
        ))
        (if (eql 2 (first (first danger))) (write-line (format nil "   Blocking: ~a" (nth 2 (first danger)))))
        (write-line "   Potential errors:")
        (loop for error in (nth 3 danger) do
            (write-line (format nil "      ~a" (first error)))
            (if (nth 1 error) (write-line (format nil "         Handled at line ~a" (nth 1 error)))
            (write-line "         NOT HANDLED"))
        )
    )
    (write-line "No dangers found"))
    (write-line "TRY-EXCEPTS:")
    (if *exceptblocks*
    (loop for e from 1 and except in *exceptblocks* do
        (write-line (format nil "EXCEPT ~a" e))
        (let ((elist '())
            (ln (nth 1 (first (nth 2 except))))
            (tu (nth 2 (first (nth 2 except)))))
            (loop for ex in (nth 2 except) do
                (if (eql ln (nth 1 ex)) (push (first ex) elist)
                (progn
                    (write-line (format nil "   ~{~a~^, ~}" (reverse elist)))
                    (write-line (format nil "      Line: ~a" ln))
                    (write-line (format nil "      Times used: ~a" tu))
                    (setf elist (list (first ex)))
                    (setf ln (nth 1 ex))
                    (setf tu (nth 2 ex))
                ))
            )
            (write-line (format nil "   ~{~a~^, ~}" (reverse elist)))
            (write-line (format nil "      Line: ~a" ln))
            (write-line (format nil "      Times used: ~a" tu))
        )
    )
    (write-line "No try-excepts used"))
)

; Function to calculate the final score
(defun calculate-score ()
    (let ((expected 0)
        (score 0))
        (loop for danger in *dangers* do
            (setf expected (+ expected (* 2 (length (nth 3 danger)))))
            (loop for error in (nth 3 danger) do
                (if (nth 1 error) (setf score (+ score 2)))
            )
        )
        (if *exceptblocks* (loop for except in *exceptblocks* do
            (setf expected (+ expected (length (nth 2 except))))
            (loop for err in (nth 2 except) do
                (if (> 2 (nth 2 err)) (setf score (+ score 1)))
                (if (or (string= "Exception" (first err)) (string= ":" (first err))) (setf expected (+ expected 1)))
            )
        ))
        (floor (* (/ score expected) 100))
    )
)

; Function to print the final suggestions
(defun generate-suggestions ()
    (write-line "RESPONSE TO CHATGPT:")
    (write-line "Redo the previous code with the following fixes:")
    (loop for danger in *dangers* do
        (let ((unhandled '()))
            (dolist (err (nth 3 danger) unhandled)
                (when (null (nth 1 err))
                (push (first err) unhandled)))
            (if (nth 5 danger)
                (if unhandled (write-line (format nil "   The try-except protecting the ~a code at line ~a doesn't handle ~{~a~^, ~}." (nth 1 (first danger)) (nth 2 danger) (reverse unhandled))))
                (if unhandled (write-line (format nil "   Unhandled ~a code at line ~a could cause ~{~a~^, ~}." (nth 1 (first danger)) (nth 2 danger) (reverse unhandled))))
            )
        )
    )
    (if *exceptblocks*
        (loop for except in *exceptblocks* do
            (let ((lnlst '()))
                (loop for ex in (nth 2 except) do
                    (if (or (string= "Exception" (first ex)) (string= ":" (first ex)))
                        (write-line (format nil "   Remove the generic exception at line ~a." (nth 1 ex))))
                    (if (> (length (nth 4 ex)) 1)
                        (loop for line in (nth 4 ex) do
                        (unless (member line lnlst) (push line lnlst)))
                    )
                )
                (when (> (length lnlst) 1)
                    (write-string "   Errors from lines ")
                    (loop for i from 1 and num in lnlst do
                        (if (and (/= i 1) (/= i (length lnlst)))
                            (princ ", "))
                        (if (eql i (length lnlst))
                            (princ " and "))
                        (princ num))
                    (write-line " should be handled separately.")
                )
            )
        )
    )
)