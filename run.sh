i=1
while cargo test test_deposit_request_top_up -- --nocapture; do
  echo "=== Test passed (iteration $i) ==="
  ((i++))
done
echo "=== Test failed on iteration $i ==="

Or if you want to capture all output to a file while also seeing it on screen:

i=1
while cargo test test_deposit_request_top_up -- --nocapture 2>&1 | tee test_output_$i.log; do
  echo "=== Test passed (iteration $i) ==="
  ((i++))
done
echo "=== Test failed on iteration $i ==="
