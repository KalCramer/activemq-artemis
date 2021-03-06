/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.activemq.artemis.utils.critical;

import java.util.concurrent.TimeUnit;

import org.junit.Assert;
import org.junit.Test;

public class CriticalMeasureTest {

   @Test
   public void testCriticalMeasure() throws Exception {
      CriticalMeasure measure = new CriticalMeasure(null, 1);
      long time = System.nanoTime();
      CriticalMeasure.TIME_ENTER_UPDATER.set(measure, time - TimeUnit.MINUTES.toNanos(5));
      CriticalMeasure.TIME_LEFT_UPDATER.set(measure, time);
      Assert.assertFalse(measure.checkExpiration(TimeUnit.SECONDS.toNanos(30), false));
   }

   @Test
   public void testCriticalMeasureTakingLongButSucceeding() throws Exception {
      CriticalAnalyzer analyzer = new CriticalAnalyzerImpl();
      CriticalComponent component = new CriticalComponentImpl(analyzer, 5);
      CriticalMeasure measure = new CriticalMeasure(component, 1);
      long time = System.nanoTime();
      CriticalMeasure.TIME_ENTER_UPDATER.set(measure, time - TimeUnit.MINUTES.toNanos(5));
      measure.leaveCritical();
      Assert.assertFalse(measure.checkExpiration(TimeUnit.SECONDS.toNanos(30), false));
   }

   @Test
   public void testCriticalFailure() throws Exception {
      CriticalAnalyzer analyzer = new CriticalAnalyzerImpl();
      CriticalComponent component = new CriticalComponentImpl(analyzer, 5);
      CriticalMeasure measure = new CriticalMeasure(component, 1);
      long time = System.nanoTime();
      measure.enterCritical();
      CriticalMeasure.TIME_ENTER_UPDATER.set(measure, time - TimeUnit.MINUTES.toNanos(5));
      CriticalMeasure.TIME_LEFT_UPDATER.set(measure, time - TimeUnit.MINUTES.toNanos(10));
      Assert.assertTrue(measure.checkExpiration(TimeUnit.SECONDS.toNanos(30), false));
      measure.leaveCritical();
   }
}
